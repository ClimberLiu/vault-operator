#! /bin/bash

trap 'cleanup' SIGINT SIGTERM SIGQUIT ERR EXIT

usage()
{
cat <<-EOF
usage: $0 -e <ENVIRONMENT> [-n <consul_namespace>] [-r <consul-helm_release_name>]
Ex., setupVaultCluster.sh -e ENG
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
    CONSUL_CLIENT=$(kubectl get pods -n ${CONSUL_NS} -l 'release in (consulcks-agent, consul),component=client' --field-selector status.phase=Running -o jsonpath='{.items[0].metadata.name}')
    if [[ ${CONSUL_CLIENT} != "" ]]
    then
        if [[ ${ENVIRONMENT} = "ENG" ]]
        then
            echo "===>Get the ca, cert and key files from consul client pods."
            kubectl cp -n ${CONSUL_NS} ${CONSUL_CLIENT}:/consul/tls/ca/..data/tls.crt ${TMPDIR}/ca_file.crt &> /dev/null
            kubectl cp -n ${CONSUL_NS} ${CONSUL_CLIENT}:/consul/tls/client/tls.crt ${TMPDIR}/cert_file.crt &> /dev/null
            kubectl cp -n ${CONSUL_NS} ${CONSUL_CLIENT}:/consul/tls/client/tls.key ${TMPDIR}/key_file.key &> /dev/null
        else
            echo "===>Get the ca, cert and key files from consul agent ca cert secret in consul's namespace."
            secret_name=$(kubectl get secret -n ${CONSUL_NS} -o name | grep consul-agent-ca-cert)
            kubectl get ${secret_name} -n ${CONSUL_NS} -o jsonpath='{.data.ca_file}' | base64 -d > ${TMPDIR}/ca_file.crt
            kubectl get ${secret_name} -n ${CONSUL_NS} -o jsonpath='{.data.cert_file}' | base64 -d > ${TMPDIR}/cert_file.crt
            kubectl get ${secret_name} -n ${CONSUL_NS} -o jsonpath='{.data.key_file}' | base64 -d > ${TMPDIR}/key_file.key
        fi
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

    # for the ENG env, use the wildcard tls secrets created during the namespace creation by the jenkins job generic-k8s-environment-create
    wildcard_sect=$(kubectl get secret -n ${VAULT_NS} -o name | grep wildcard | grep -v wildcard.${VAULT_NS})
    if [[ ${wildcard_sect} != "" ]]
    then
        kubectl get ${wildcard_sect} -n ${VAULT_NS} -o jsonpath='{.data.tls\.key}' | base64 -d > ${TMPDIR}/vault.key
        kubectl get ${wildcard_sect} -n ${VAULT_NS} -o jsonpath='{.data.tls\.crt}' | base64 -d > ${TMPDIR}/vault.crt
        curl ${SPANETCA_CERT_URL} --output ${TMPDIR}/vault.ca
    else
        # Use self signed certificate if the wildcard tls secrets not exist.
        SERVICE=wildcard
        CSR_NAME=vault-csr
        openssl genrsa -out ${TMPDIR}/vault.key 2048
        cat <<EOF >${TMPDIR}/csr.conf
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${SERVICE}
DNS.2 = ${SERVICE}.${VAULT_NS}
DNS.3 = ${SERVICE}.${VAULT_NS}.svc
DNS.4 = ${SERVICE}.${VAULT_NS}.svc.cluster.local
IP.1 = 127.0.0.1
EOF
        openssl req -new -key ${TMPDIR}/vault.key -subj "/CN=${SERVICE}.${VAULT_NS}.svc" -out ${TMPDIR}/server.csr -config ${TMPDIR}/csr.conf
        cat <<EOF >${TMPDIR}/csr.yaml
apiVersion: certificates.k8s.io/v1beta1
kind: CertificateSigningRequest
metadata:
  name: ${CSR_NAME}
spec:
  groups:
  - system:authenticated
  request: $(cat ${TMPDIR}/server.csr | base64 | tr -d '\n')
  usages:
  - digital signature
  - key encipherment
  - server auth
EOF
        kubectl create -f ${TMPDIR}/csr.yaml
        kubectl certificate approve ${CSR_NAME}
        serverCert=$(kubectl get csr ${CSR_NAME} -o jsonpath='{.status.certificate}')
        echo "${serverCert}" | openssl base64 -d -A -out ${TMPDIR}/vault.crt
        kubectl config view --raw --minify --flatten -o jsonpath='{.clusters[].cluster.certificate-authority-data}' | base64 -d > ${TMPDIR}/vault.ca

    fi
    echo "===>Store the key, cert, and SAPNet_CA into Kubernetes secret ${SECRET_NAME}."
    kubectl create secret generic ${SECRET_NAME} --namespace ${VAULT_NS} --from-file=vault.key=${TMPDIR}/vault.key \
        --from-file=vault.crt=${TMPDIR}/vault.crt --from-file=vault.ca=${TMPDIR}/vault.ca
}

generate_consul_acl_token_for_vault()
{
    echo "===>Get the consul's bootstrap token from k8s"
    bootstrap_token=$(kubectl get secret ${CONSUL_RELEASE}-consul-bootstrap-acl-token -n ${CONSUL_NS} -o jsonpath='{.data.token}' | base64 -d)
    consul_server_pod=$(kubectl get pods -n ${CONSUL_NS} -l 'release in (consulcks-agent, consul),component=server' --field-selector status.phase=Running -o jsonpath='{.items[0].metadata.name}')

    echo "===>Create the acl policy for vault in consul server pod ${consul_server_pod}"
    kubectl cp -n ${CONSUL_NS} templates/vault-acl-policy.hcl ${consul_server_pod}:/tmp/vault-acl-policy.hcl
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
        sed "s/<CONSUL_ACL_TOKEN>/${token}/" templates/${VAULT_VALUES_FILE} > /tmp/${VAULT_VALUES_FILE}.$$
    fi

}

get_consul_acl_token_from_azure_keyvault()
{
    tenant_id=$(echo NDJmNzY3NmMtZjQ1NS00MjNjLTgyZjYtZGMyZDk5NzkxYWY3Cg== | base64 -d)
    client_sec=$(echo cG1ISWZTbURqYUs4bXNXUWNjbGRpazBGMHpsSHVkTU9qRlZlbjg4TU9jYz0K | base64 -d)
    client_id=$(echo MGZlMTkzZWEtNzZmZS00ZTlmLWI3N2MtNGJhNTlmY2M1OTM4Cg== | base64 -d)
    secret_name=$1
    bearer_token=$(curl -X POST https://login.microsoftonline.com/${tenant_id}/oauth2/token -d "grant_type=client_credentials&client_id=${client_id}&client_secret=${client_sec}&resource=https://vault.azure.net" --insecure | jq '.access_token' | tr -d \")
    secret_version=$(curl -X GET "https://consulopensslvault.vault.azure.net/secrets/${secret_name}/versions?maxresults=1&api-version=7.0" -H "Authorization: Bearer ${bearer_token}" -H 'Content-Type: application/json' --insecure | jq '.value[0].id' | tr -d \")
    token=$(curl -X GET "${secret_version}?api-version=7.0" -H "Authorization: Bearer ${bearer_token}" -H 'Content-Type: application/json' --insecure | jq '.value' | tr -d \")
    sed "s/<CONSUL_ACL_TOKEN>/${token}/" templates/${VAULT_VALUES_FILE} > /tmp/${VAULT_VALUES_FILE}.$$
}

update_vault_services_annotations()
{
    dns_suffix=$(kubectl get secret -n ${VAULT_NS} -o name | grep wildcard.${VAULT_NS} | sed "s#secret/wildcard.${VAULT_NS}##")
    sed -i.bak "s#<VAULT_DNS>#vault.${dns_suffix}#; s#<VAULT_UI_DNS>#vault-ui.${dns_suffix}#" /tmp/${VAULT_VALUES_FILE}.$$ && rm /tmp/${VAULT_VALUES_FILE}.$$.bak
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
        helm install -f /tmp/${VAULT_VALUES_FILE}.$$ ${VAULT_RELEASE} ../vault-helm -n ${VAULT_NS}
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
    kubectl cp -n ${VAULT_NS} templates/admin-policy.hcl ${vault_server}:/tmp/admin-policy.hcl
    kubectl cp -n ${VAULT_NS} templates/provisioner-policy.hcl ${vault_server}:/tmp/provisioner-policy.hcl
    kubectl exec -n ${VAULT_NS} ${vault_server} -- sh -c "export VAULT_TOKEN=${root_token}; vault policy write -tls-skip-verify admin /tmp/admin-policy.hcl; vault policy write -tls-skip-verify provisioner /tmp/provisioner-policy.hcl"
    kubectl exec -n ${VAULT_NS} ${vault_server} -- sh -c "export VAULT_TOKEN=${root_token}; vault token create -tls-skip-verify -policy=admin -format=json 2> /dev/null" > ${admin_token_json}
    kubectl exec -n ${VAULT_NS} ${vault_server} -- sh -c "export VAULT_TOKEN=${root_token}; vault token create -tls-skip-verify -policy=provisioner -format=json 2> /dev/null" > ${provisioner_token_json}
    admin_token=$(jq '.auth.client_token' ${admin_token_json} | tr -d \")
    provisioner_token=$(jq '.auth.client_token' ${provisioner_token_json} | tr -d \")
    kubectl create secret generic vault-admin-token --from-literal=token=${admin_token} -n ${VAULT_NS}
    kubectl create secret generic vault-provisioner-token --from-literal=token=${provisioner_token} -n ${VAULT_NS}

    # get idl-vault-admin token related policies
    idl_vault_admin_dir=hashicorp-vault-local-setup
    if [[ ! -d ../${idl_vault_admin_dir} ]]
    then
        current_dir=$(pwd)
        parent_dir=$(dirname ${current_dir})
        git clone ${IDL_VAULT_ADMIN_GITURL} ${parent_dir}/${idl_vault_admin_dir}
    fi

    if [[ -d ../${idl_vault_admin_dir} ]]
    then
        current_dir=$(pwd)
        parent_dir=$(dirname ${current_dir})
        idl_vault_admin_policy_name="idl-vault-admin"
        idl_vault_crud_policy_name="idl-vault-secrets-crud"
        default_max_ttl_vault_config="8760h"
        idl_vault_admin_token_json=/tmp/idl_vault_admin_token_$$.json

        kubectl cp -n ${VAULT_NS} ${parent_dir}/${idl_vault_admin_dir}/config ${vault_server}:/tmp/config
        kubectl exec -n ${VAULT_NS} ${vault_server} -- sh -c "export VAULT_TOKEN=${root_token}; vault policy write -tls-skip-verify ${idl_vault_admin_policy_name} /tmp/config/${idl_vault_admin_policy_name}.hcl; vault policy write -tls-skip-verify ${idl_vault_crud_policy_name} /tmp/config/${idl_vault_crud_policy_name}.hcl"
        kubectl exec -n ${VAULT_NS} ${vault_server} -- sh -c "export VAULT_TOKEN=${root_token}; vault token create -tls-skip-verify -policy=${idl_vault_admin_policy_name} -period=${default_max_ttl_vault_config} -format=json 2> /dev/null" > ${idl_vault_admin_token_json}
        kubectl exec -n ${VAULT_NS} ${vault_server} -- sh -c "export VAULT_TOKEN=${root_token} VAULT_SKIP_VERIFY=true; cd /tmp/config/ && sh delta.sh"
        idl_vault_admin_token=$(jq '.auth.client_token' ${idl_vault_admin_token_json} | tr -d \")
        kubectl create secret generic idl-vault-admin-token --from-literal=token=${idl_vault_admin_token} -n ${VAULT_NS}
    else
        echo "!!!The idl-vault-admin hcl related git repo is not exist in ../${idl_vault_admin_dir}"
        exit 1
    fi

    kubectl exec -n ${VAULT_NS} ${vault_server} -- sh -c "export VAULT_TOKEN=${root_token}; vault secrets enable -tls-skip-verify -path=secret kv-v2"
}

cleanup()
{
    rm -f ${TMPDIR}/ca_file.crt ${TMPDIR}/cert_file.crt ${TMPDIR}/key_file.key
    rm -f ${TMPDIR}/vault.key ${TMPDIR}/vault.crt ${TMPDIR}/vault.ca
    rm -f ${TMPDIR}/server.csr ${TMPDIR}/csr.conf ${TMPDIR}/csr.yaml
    rm -f /tmp/${VAULT_VALUES_FILE}.$$
    rm -f ${INIT_TOKEN_FILE}
    rm -f /tmp/vault_admin_token_$$.json /tmp/vault_provisioner_token_$$.json /tmp/idl_vault_admin_token_$$.json
}

CONSUL_NS=consul
CONSUL_RELEASE=consul
VAULT_NS=vault
VAULT_RELEASE=vault
INIT_TOKEN_FILE=/tmp/init_token_$$.json
DC=""
VAULT_HELM_GITURL=https://github.com/hashicorp/vault-helm.git
VAULT_HELM_VER=v0.3.3
SPANETCA_CERT_URL=http://aia.pki.co.sap.com/aia/SAPNetCA_G2.crt
IDL_VAULT_ADMIN_GITURL=https://github.wdf.sap.corp/sfsf-platform-core/hashicorp-vault-local-setup.git
eflag=0
while getopts :n:r:d:e: opt
do
    case "$opt" in
        n)
            CONSUL_NS=$OPTARG
            ;;
        r)
            CONSUL_RELEASE=$OPTARG
            ;;
        d)
            DC=$(echo ${OPTARG} | tr a-z A-Z)
            if [[ ! ${DC} =~ ^DC[0-9]{1,3}$ ]]
            then
                echo "Invalid value for option -d, please pass the value with format, such as dc8, dc47."
                exit 2
            fi
            ;;
        e)
            eflag=1
            ENVIRONMENT=$(echo ${OPTARG} | tr a-z A-Z)
            if [[ ${ENVIRONMENT} = "ENG" ]]
            then
                VAULT_VALUES_FILE=helm-vault-values-eng.yaml
            elif [[ ${ENVIRONMENT} = "QA" || ${ENVIRONMENT} = "PREVIEW" || ${ENVIRONMENT} = "PROD" ]]
            then
                VAULT_VALUES_FILE=helm-vault-values.yaml
            else
                echo "Invalid argument for option -e: $OPTARG"
                exit 2
            fi
            ;;
        ?)
            echo "Invalid option: -$OPTARG"
            usage
            exit 2
    esac
done

if [[ ${eflag} -eq 0 ]]
then
  echo "The -e option is mandatory"
  usage
  exit 2
fi

check_consul_setup
check_vault_namespace
create_k8s_secret_for_consul_storage_tls
create_k8s_secret_for_vault_tls
if [[ ${ENVIRONMENT} = "ENG" ]]
then
    generate_consul_acl_token_for_vault
    update_vault_services_annotations
else
    get_consul_acl_token_from_azure_keyvault ${DC}"-write-acl-token"

fi
install_vault_helm_chart
unseal_vault_cluster
create_admin_and_provisioner_token