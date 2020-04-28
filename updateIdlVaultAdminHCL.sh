#! /bin/bash

VAULT_NS=vault
VAULT_RELEASE=vault
IDL_VAULT_ADMIN_GITURL=https://github.wdf.sap.corp/sfsf-platform-core/hashicorp-vault-local-setup.git
vault_server=$(kubectl get pods -n ${VAULT_NS} -l app.kubernetes.io/name=vault,component=server --field-selector status.phase=Running -o jsonpath='{.items[0].metadata.name}')
root_token=""
idl_vault_admin_dir=hashicorp-vault-local-setup

usage()
{
cat <<-EOF
usage: $0 [-n <consul_namespace>] [-t <root-token>]
EOF
}

while getopts :t: opt
do
    case "$opt" in
        t)
            root_token=$OPTARG
            ;;
        ?)
            echo "Invalid option: -$OPTARG"
            usage
            exit 2
    esac
done

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
    kubectl create secret generic idl-vault-admin-token --from-literal=token=${idl_vault_admin_token} -n ${VAULT_NS} --dry-run --save-config=false -o yaml | kubectl apply -f -
else
    echo "!!!The idl-vault-admin hcl related git repo is not exist in ../${idl_vault_admin_dir}"
    exit 1
fi