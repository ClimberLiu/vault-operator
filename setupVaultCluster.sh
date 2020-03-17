#! /bin/bash

trap 'cleanup' SIGINT SIGTERM SIGQUIT ERR EXIT

usage()
{
cat <<-EOF
usage: $0 [-n <consul_namespace>] [-r <consul-helm_release_name>]
EOF
}

check_consul_setup()
{
    # Make sure to have the consul cluster ready first
    kubectl get ns ${CONSUL_NS} -o jsonpath='{.metadata.name}' &> /dev/null
    if [[ $? -eq 0 ]]
    then
        kubectl get daemonset -n ${CONSUL_NS} -o jsonpath='{.items[0].metadata.name}' &> /dev/null
        if [[ $? -eq 0 ]]
        then
            echo "===>Consul is there, continue..."
        else
            echo "The consul client daemonset looks not ready, please check the consul namespace and consul helm setup."
            exit 1
        fi
    else
        echo "The namespace ${CONSUL_NS} is not exist, please create it first."
        echo "If you installed the consul-helm chart in different namespace and you meant to use that namespace, please use -n option to pass in the namespace name."
        exit 1
    fi
}

create_k8s_secret_for_consul_storage_tls()
{
    # From consul client pods, get the ca, cert and key files and store them in kubernetes secrects store for the Vault's consul storage TLS-related config
    TMPDIR=/tmp
    CONSUL_CLIENT=$(kubectl get pods -n ${CONSUL_NS} -l release=${CONSUL_RELEASE},component=client --field-selector status.phase=Running -o jsonpath='{.items[0].metadata.name}')
    if [[ ${CONSUL_CLIENT} != "" ]]
    then
        echo "===>Get the ca, cert and key files from consul client pods."
        kubectl cp -n ${CONSUL_NS} ${CONSUL_CLIENT}:/consul/tls/ca/..data/tls.crt ${TMPDIR}/ca_file.crt &> /dev/null
        kubectl cp -n ${CONSUL_NS} ${CONSUL_CLIENT}:/consul/tls/client/tls.crt ${TMPDIR}/cert_file.crt &> /dev/null
        kubectl cp -n ${CONSUL_NS} ${CONSUL_CLIENT}:/consul/tls/client/tls.key ${TMPDIR}/key_file.key &> /dev/null

        if [[ -f ${TMPDIR}/ca_file.crt && -f ${TMPDIR}/cert_file.crt && -f ${TMPDIR}/key_file.key ]]
        then
            echo "===>Store the ca, cert and key in kubernetes secrects store."
            kubectl create secret generic consul-client-tls --namespace ${VAULT_NS} --from-file=ca_file.crt=${TMPDIR}/ca_file.crt \
            --from-file=cert_file.crt=${TMPDIR}/cert_file.crt --from-file=key_file.key=${TMPDIR}/key_file.key
        else
            echo "Failed to copy ca, cert and key files from consul client pods, please check!"
            exit 1
        fi
    else
        echo "Could not find the consul client pod! Please check the consul-helm chart's release name and make sure the client is enabled in consul-helm values YAML."
        exit 1
    fi
}

check_vault_namespace()
{
    kubectl get ns ${VAULT_NS} -o jsonpath='{.metadata.name}' &> /dev/null
    if [[ $? -eq 0 ]]
    then
        echo "===>The vault namespace ${VAULT_NS} is there, continue..."
    else
        echo "The vault namespace ${VAULT_NS} is not exist, please use jenkins job https://saas-manager.mo.sap.corp/job/generic-k8s-environment-create/ to create it first."
        exit 1
    fi
}

create_k8s_secret_for_vault_tls()
{
    # Create and Store key, cert and SAPNet_CA in kubernetes secrets store for Vault cluster with TLS
    SECRET_NAME=vault-server-tls
    TMPDIR=/tmp

    wildcard_sect=$(kubectl get secret -n ${VAULT_NS} -o name | grep wildcard | grep -v wildcard.${VAULT_NS})
    kubectl get ${wildcard_sect} -n ${VAULT_NS} -o jsonpath='{.data.tls\.key}' | base64 -d > ${TMPDIR}/vault.key
    kubectl get ${wildcard_sect} -n ${VAULT_NS} -o jsonpath='{.data.tls\.crt}' | base64 -d > ${TMPDIR}/vault.crt
    curl ${SPANETCA_CERT_URL} --output ${TMPDIR}/vault.ca
    echo "===>Store the key, cert, and Kubernetes CA into Kubernetes secret ${SECRET_NAME}."
    kubectl create secret generic ${SECRET_NAME} --namespace ${VAULT_NS} --from-file=vault.key=${TMPDIR}/vault.key \
        --from-file=vault.crt=${TMPDIR}/vault.crt --from-file=vault.ca=${TMPDIR}/vault.ca
}

generate_consul_acl_token_for_vault()
{
    echo "===>Get the consul's bootstrap token from k8s"
    bootstrap_token=$(kubectl get secret ${CONSUL_RELEASE}-consul-bootstrap-acl-token -n ${CONSUL_NS} -o jsonpath='{.data.token}' | base64 -d)
    consul_server_pod=$(kubectl get pods -n ${CONSUL_NS} -l release=${CONSUL_RELEASE},component=server --field-selector status.phase=Running -o jsonpath='{.items[0].metadata.name}')

    echo "===>Create the acl policy for vault in consul server pod ${consul_server_pod}"
    kubectl cp -n ${CONSUL_NS} vault-acl-policy.hcl ${consul_server_pod}:/tmp/vault-acl-policy.hcl
    kubectl exec ${consul_server_pod} -n ${CONSUL_NS} -- sh -c "export CONSUL_HTTP_TOKEN=${bootstrap_token}; consul acl policy create -name vault-acl -rules @/tmp/vault-acl-policy.hcl"

    echo "===>Create the token with the policy created above for vault."
    token=$(uuidgen -t 2> /dev/null | tr '[:upper:]' '[:lower:]')
    if [[ ${token} = "" ]]
    then
        token=$(uuidgen 2> /dev/null | tr '[:upper:]' '[:lower:]')
    fi
    kubectl exec -it ${consul_server_pod} -n ${CONSUL_NS} -- sh -c "export CONSUL_HTTP_TOKEN=${bootstrap_token}; consul acl token create -description 'Token for Hashicorp Vault' -policy-name vault-acl -secret=${token}" &> /dev/null
    if [[ $? -ne 0 ]]
    then
        echo "Failed to create consul ACL token for vault! Exit..."
        exit 1
    else
        sed "s/<CONSUL_ACL_TOKEN>/${token}/" ${VAULT_VALUES_FILE} > ${VAULT_VALUES_FILE}.$$
    fi

}

update_vault_services_annotations()
{
    dns_suffix=$(kubectl get secret -n ${VAULT_NS} -o name | grep wildcard.${VAULT_NS} | sed "s#secret/wildcard.${VAULT_NS}##")
    sed -i "s/<VAULT_DNS>/vault.${dns_suffix}/" ${VAULT_VALUES_FILE}.$$
    sed -i "s/<VAULT_UI_DNS>/vault-ui.${dns_suffix}/" ${VAULT_VALUES_FILE}.$$
}

install_vault_helm_chart()
{
    if [[ ! -d ../vault-helm ]]
    then
        current_dir=$(pwd)
        parent_dir=$(dirname ${current_dir})
        # tested the vault-helm chart v0.3.3 with this script in HCM-ENG/cls02 k8s cluster.
        echo "===>The vault-helm chart is not exists in ${parent_dir}, clone vault-helm repository (${VAULT_HELM_GITURL}) into ${parent_dir}"
        git clone ${VAULT_HELM_GITURL} ${parent_dir}/vault-helm
        cd ${parent_dir}/vault-helm && git checkout ${VAULT_HELM_VER}
        cd ${current_dir}
    fi

    if [[ -d ../vault-helm ]]
    then
        echo "===>Install vault helm chart in namespace ${VAULT_NS}"
        echo "====================================================="
        helm install -f ${VAULT_VALUES_FILE}.$$ ${VAULT_RELEASE} ../vault-helm -n ${VAULT_NS}
        echo "====================================================="
    else
        echo "!!!The vault-helm chart is not exist in current dir ${parent_dir}"
        exit 1
    fi
}

unseal_vault_cluster()
{
    VAULT_SERVER_LIST=""
    until [[ ${VAULT_SERVER_LIST} != "" ]]
    do
        echo "===>Waiting the vault pods to be ready..."
        VAULT_SERVER_LIST=$(kubectl get pods -n ${VAULT_NS} -l app.kubernetes.io/name=vault,component=server --field-selector status.phase=Running -o jsonpath='{.items[*].metadata.name}')
        sleep 1
    done
    VAULT_SERVER_ONE=${VAULT_SERVER_LIST%% *}
    echo "===>Initialize vault"
    kubectl exec ${VAULT_SERVER_ONE} -n ${VAULT_NS} -- vault operator init -tls-skip-verify -format=json > ${INIT_TOKEN_FILE}
    if [[ $? -eq 0 ]]
    then
        echo "================================================="
        cat ${INIT_TOKEN_FILE}
cat <<EOF
Vault initialized with 5 key shares and a key threshold of 3. Please securely
distribute the key shares printed above. When the Vault is re-sealed,
restarted, or stopped, you must supply at least 3 of these keys to unseal it
before it can start servicing requests.

Vault does not store the generated master key. Without at least 3 key to
reconstruct the master key, Vault will remain permanently sealed!

It is possible to generate new unseal keys, provided you have a quorum of
existing unseal keys shares. See "vault operator rekey" for more information.
EOF
        echo "================================================="
    else
        echo "Failed to initialize vault! Exit.."
        exit 1
    fi
    for server in ${VAULT_SERVER_LIST}
    do
        echo "===>Unseal the vault on server ${server}"
        for i in 0 1 2
        do
            key=$(jq ".unseal_keys_b64[$i]" ${INIT_TOKEN_FILE} | tr -d  \")
            kubectl exec ${server} -n ${VAULT_NS} -- vault operator unseal -tls-skip-verify ${key}
        done
    done
}

create_admin_and_provisioner_token()
{
    vault_server=$(kubectl get pods -n ${VAULT_NS} -l app.kubernetes.io/name=vault,component=server --field-selector status.phase=Running -o jsonpath='{.items[0].metadata.name}')
    root_token=$(jq ".root_token" ${INIT_TOKEN_FILE} | tr -d  \")
    admin_token_json=/tmp/vault_admin_token_$$.json
    provisioner_token_json=/tmp/vault_provisioner_token_$$.json
    kubectl cp -n ${VAULT_NS} admin-policy.hcl ${vault_server}:/tmp/admin-policy.hcl
    kubectl cp -n ${VAULT_NS} provisioner-policy.hcl ${vault_server}:/tmp/provisioner-policy.hcl
    kubectl exec -n ${VAULT_NS} ${vault_server} -- sh -c "export VAULT_CACERT=/vault/userconfig/vault-server-tls/vault.ca VAULT_TOKEN=${root_token}; vault policy write admin /tmp/admin-policy.hcl; vault policy write provisioner /tmp/provisioner-policy.hcl"
    kubectl exec -n ${VAULT_NS} ${vault_server} -- sh -c "export VAULT_CACERT=/vault/userconfig/vault-server-tls/vault.ca VAULT_TOKEN=${root_token}; vault token create -policy=admin -format=json 2> /dev/null" > ${admin_token_json}
    kubectl exec -n ${VAULT_NS} ${vault_server} -- sh -c "export VAULT_CACERT=/vault/userconfig/vault-server-tls/vault.ca VAULT_TOKEN=${root_token}; vault token create -policy=provisioner -format=json 2> /dev/null" > ${provisioner_token_json}
    admin_token=$(jq '.auth.client_token' ${admin_token_json} | tr -d \")
    provisioner_token=$(jq '.auth.client_token' ${provisioner_token_json} | tr -d \")
    kubectl create secret generic vault-admin-token --from-literal=token=${admin_token} -n ${VAULT_NS}
    kubectl create secret generic vault-provisioner-token --from-literal=token=${provisioner_token} -n ${VAULT_NS}

    # get idl-vault-admin token related policies
    idl_vault_admin_policy_name="idl-vault-admin"
    idl_vault_crud_policy_name="idl-vault-secrets-crud"
    default_max_ttl_vault_config="8760h"
    idl_vault_admin_token_json=/tmp/idl_vault_admin_token_$$.json
    curl ${IDL_VAULT_ADMIN_HCL_URL} --output /tmp/${idl_vault_admin_policy_name}.hcl
    curl ${IDL_VAULT_SECRETS_CRUD_HCL_URL} --output /tmp/${idl_vault_crud_policy_name}.hcl
    kubectl cp -n ${VAULT_NS} /tmp/${idl_vault_admin_policy_name}.hcl ${vault_server}:/tmp/${idl_vault_admin_policy_name}.hcl
    kubectl cp -n ${VAULT_NS} /tmp/${idl_vault_crud_policy_name}.hcl ${vault_server}:/tmp/${idl_vault_crud_policy_name}.hcl
    kubectl exec -n ${VAULT_NS} ${vault_server} -- sh -c "export VAULT_CACERT=/vault/userconfig/vault-server-tls/vault.ca VAULT_TOKEN=${root_token}; vault policy write ${idl_vault_admin_policy_name} /tmp/${idl_vault_admin_policy_name}.hcl; vault policy write ${idl_vault_crud_policy_name} /tmp/${idl_vault_crud_policy_name}.hcl"
    kubectl exec -n ${VAULT_NS} ${vault_server} -- sh -c "export VAULT_CACERT=/vault/userconfig/vault-server-tls/vault.ca VAULT_TOKEN=${root_token}; vault token create -policy=${idl_vault_admin_policy_name} -period=${default_max_ttl_vault_config} -format=json 2> /dev/null" > ${idl_vault_admin_token_json}
    idl_vault_admin_token=$(jq '.auth.client_token' ${idl_vault_admin_token_json} | tr -d \")
    kubectl create secret generic idl-vault-admin-token --from-literal=token=${idl_vault_admin_token} -n ${VAULT_NS}
    kubectl exec -n ${VAULT_NS} ${vault_server} -- sh -c "export VAULT_CACERT=/vault/userconfig/vault-server-tls/vault.ca VAULT_TOKEN=${root_token}; vault secrets enable -path=secret kv-v2"
}

cleanup()
{
    rm -f ${TMPDIR}/ca_file.crt ${TMPDIR}/cert_file.crt ${TMPDIR}/key_file.key
    rm -f ${TMPDIR}/csr.conf
    rm -f ${TMPDIR}/vault.key ${TMPDIR}/vault.crt ${TMPDIR}/vault.ca
    rm -f ${TMPDIR}/csr.yaml
    rm -f ${TMPDIR}/server.csr
    rm -f /tmp/${idl_vault_admin_policy_name}.hcl
    rm -f /tmp/${idl_vault_crud_policy_name}.hcl
    rm -f ${INIT_TOKEN_FILE}
}

CONSUL_NS=consul
CONSUL_RELEASE=consul
VAULT_NS=vault
VAULT_RELEASE=vault
INIT_TOKEN_FILE=/tmp/init_token_$$.json
VAULT_VALUES_FILE=helm-vault-values.yaml
VAULT_HELM_GITURL=https://github.com/hashicorp/vault-helm.git
VAULT_HELM_VER=v0.3.3
IDL_VAULT_ADMIN_HCL_URL=https://github.wdf.sap.corp/raw/I502944/hashicorp-vault/master/config/idl-vault-admin.hcl
IDL_VAULT_SECRETS_CRUD_HCL_URL=https://github.wdf.sap.corp/raw/I502944/hashicorp-vault/master/config/idl-vault-secrets-crud.hcl
SPANETCA_CERT_URL=http://aia.pki.co.sap.com/aia/SAPNetCA_G2.crt
while getopts :n:r: opt
do
    case "$opt" in
        n)
            CONSUL_NS=$OPTARG
            ;;
        r)
            CONSUL_RELEASE=$OPTARG
            ;;
        ?)
            echo "Invalid option: -$OPTARG"
            usage
            exit 2
    esac
done

check_consul_setup
check_vault_namespace
create_k8s_secret_for_consul_storage_tls
create_k8s_secret_for_vault_tls
generate_consul_acl_token_for_vault
update_vault_services_annotations
install_vault_helm_chart
unseal_vault_cluster
create_admin_and_provisioner_token