#! /bin/bash

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
            echo "Consul is there, continue..."
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

install_vault_helm_chart()
{
    if [[ -d ../vault-helm ]]
    then
        echo "Install vault helm chart which is used by the vault for auto-unseal in namespace ${CONSUL_NS}"
        helm install ${VAULT_RELEASE} ../vault-helm -n ${CONSUL_NS}
    else
        echo "!!!The vault-helm chart is not exist in current dir $(pwd)"
        exit 1
    fi
}

unseal_vault_cluster_and_setup_autounseal_pocily()
{
    VAULT_SERVER_LIST=""
    until [[ ${VAULT_SERVER_LIST} != "" ]]
    do
        echo "Waiting the vault pods (which are used for auto-unseal) to be ready..."
        VAULT_SERVER_LIST=$(kubectl get pods -n ${CONSUL_NS} -l app.kubernetes.io/name=vault,component=server --field-selector status.phase=Running -o jsonpath='{.items[*].metadata.name}')
        sleep 1
    done
    VAULT_SERVER_ONE=${VAULT_SERVER_LIST%% *}
    echo "Initialize vault (which are used for auto-unseal)"
    kubectl exec ${VAULT_SERVER_ONE} -n ${CONSUL_NS} -- vault operator init -format=json &> ${INIT_TOKEN_FILE}
    if [[ $? -eq 0 ]]
    then
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
    else
        echo "Failed to initialize vault! Exit.."
        exit 1
    fi

    # Unseal vault servers
    for server in ${VAULT_SERVER_LIST}
    do
        echo "Unseal the vault on server ${server}"
        for i in 0 1 2
        do
            key=$(jq ".unseal_keys_b64[$i]" ${INIT_TOKEN_FILE} | tr -d  \")
            kubectl exec ${server} -n ${CONSUL_NS} -- vault operator unseal ${key}
        done
    done

    # Setup auto-unseal policy
    ROOT_TOKEN=$(jq ".root_token" ${INIT_TOKEN_FILE} | tr -d  \")
    if [[ -f ./autounseal.hcl ]]
    then
        kubectl cp -n ${CONSUL_NS} ./autounseal.hcl ${VAULT_SERVER_ONE}:/tmp/autounseal.hcl
    else
        echo "The auto-unseal policy file doesn't exist in current dir, please check!"
        exit 1
    fi
    kubectl exec ${VAULT_SERVER_ONE} -n ${CONSUL_NS} -- sh -c "vault login ${ROOT_TOKEN} > /dev/null && \
                vault audit enable file file_path=/vault/logs/audit.log && \
                vault secrets enable transit && \
                vault write -f transit/keys/autounseal && \
                vault policy write autounseal /tmp/autounseal.hcl"

    WRAPPING_TOKEN=$( (kubectl exec ${VAULT_SERVER_ONE} -n ${CONSUL_NS} -- vault token create -policy="autounseal" -wrap-ttl=120 -format=json) | jq ".wrap_info.token" | tr -d  \")

    echo "Generate the client token into ${CLIENT_TOKEN_FILE}"
    (kubectl exec ${VAULT_SERVER_ONE} -n ${CONSUL_NS} -- vault unwrap -format=json ${WRAPPING_TOKEN}) > ${CLIENT_TOKEN_FILE}
}

migrate_vault_cluster_to_auto_unseal()
{
    CLIENT_TOKEN=$(jq ".auth.client_token" ${CLIENT_TOKEN_FILE} | tr -d  \")

    bootstrap_token=$(kubectl get secret ${CONSUL_RELEASE}-consul-bootstrap-acl-token -n ${CONSUL_NS} -o jsonpath='{.data.token}' | base64 -d)
    consul_server_pod=$(kubectl get pods -n ${CONSUL_NS} -l release=${CONSUL_RELEASE},component=server --field-selector status.phase=Running -o jsonpath='{.items[0].metadata.name}')
    accessor_id=$(kubectl exec ${consul_server_pod} -n ${CONSUL_NS} -- sh -c "export CONSUL_HTTP_TOKEN=${bootstrap_token}; consul acl token list | grep -B6 vault-acl | grep AccessorID " | awk -F: '{print $2}' | tr -d [:space:])
    CONSUL_ACL_TOKEN=$(kubectl exec -it ${consul_server_pod} -n ${CONSUL_NS} -- sh -c "export CONSUL_HTTP_TOKEN=${bootstrap_token}; consul acl token read -id ${accessor_id} | grep SecretID" | awk -F: '{print $2}' | tr -d [:space:])

    VAULT_FOR_AUTOUNSEAL_SERVICE_IP=$(kubectl get service -l app.kubernetes.io/instance=${VAULT_RELEASE},app.kubernetes.io/name=vault -n ${CONSUL_NS} -o jsonpath='{.items[].spec.clusterIP}')

    sed "s/<CONSUL_ACL_TOKEN>/${CONSUL_ACL_TOKEN}/;s/<VAULT_FOR_AUTOUNSEAL_SERVICE_IP>/${VAULT_FOR_AUTOUNSEAL_SERVICE_IP}/;s/<CLIENT_TOKEN>/${CLIENT_TOKEN}/" ${HELM_VALUES_FILE} > ${HELM_VALUES_FILE}.$$
    echo "========================================="
    helm upgrade -f ${HELM_VALUES_FILE}.$$ vault ../vault-helm -n ${VAULT_NS}
    echo "========================================="
    VAULT_SERVER_LIST=$(kubectl get pods -n ${VAULT_NS} -l app.kubernetes.io/name=vault,component=server -o jsonpath='{.items[*].metadata.name}')
    for server in ${VAULT_SERVER_LIST}
    do
        kubectl delete pod ${server} -n ${VAULT_NS}
    done

cat <<-EOF
The vault-helm chart has been upgraded with auto-unseal setup.
To migrate the current vault cluster to auto-unseal, please run the following commands with shared keys in one of the vault server pods, and then delete other vault server pods.
export VAULT_CACERT=/vault/userconfig/vault-server-tls/vault.ca; vault operator unseal -migrate

After that, all vault server pods should be running and unsealed.
EOF

}


CONSUL_NS=consul
CONSUL_RELEASE=consul
VAULT_NS=vault
VAULT_RELEASE=vault-for-auto-unseal
INIT_TOKEN_FILE=/tmp/init_token_$$.json
CLIENT_TOKEN_FILE=/tmp/client_token_$$.json
HELM_VALUES_FILE=helm-vault-values_for_migrating_to_auto-unseal.yaml

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
install_vault_helm_chart
unseal_vault_cluster_and_setup_autounseal_pocily
migrate_vault_cluster_to_auto_unseal

