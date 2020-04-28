#! /bin/bash

VAULT_NS=vault
VAULT_RELEASE=vault
IDL_VAULT_ADMIN_GITURL=https://github.wdf.sap.corp/sfsf-platform-core/hashicorp-vault-local-setup.git
vault_server=$(kubectl get pods -n ${VAULT_NS} -l app.kubernetes.io/name=vault,component=server --field-selector status.phase=Running -o jsonpath='{.items[0].metadata.name}')
root_token=$(jq ".root_token" ${INIT_TOKEN_FILE} | tr -d  \")
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
    idl_vault_admin_token_json=/tmp/idl_vault_admin_token_$$.json

    kubectl cp -n ${VAULT_NS} ${parent_dir}/${idl_vault_admin_dir} ${vault_server}:/tmp/${idl_vault_admin_dir}
    kubectl exec -n ${VAULT_NS} ${vault_server} -- sh -c "export VAULT_TOKEN=${root_token}; cd /tmp/${idl_vault_admin_dir}/config/ && sh configureAdmin.sh"
    idl_vault_admin_token=$(jq '.auth.client_token' ${idl_vault_admin_token_json} | tr -d \")
    kubectl create secret generic idl-vault-admin-token --from-literal=token=${idl_vault_admin_token} -n ${VAULT_NS} --dry-run --save-config=false -o yaml | kubectl apply -f -
else
    echo "!!!The idl-vault-admin hcl related git repo is not exist in ../${idl_vault_admin_dir}"
    exit 1
fi