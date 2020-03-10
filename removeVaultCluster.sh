#!/bin/bash -

read -p "!!!Are you sure to remove the vault cluster and namespace? [y/n] " input
case ${input} in
    [yY]*)
        echo "Removing vault cluster and namespace..."
        ;;
    [nN]*)
        exit
        ;;
    *)
        echo "Just enter y or n, please."
        exit
        ;;
esac

CSR_NAME=vault-csr
VAULT_NS=vault
VAULT_RELEASE=vault
CONSUL_NS=consul
CONSUL_RELEASE=consul

helm uninstall ${VAULT_RELEASE} -n ${VAULT_NS}
kubectl delete ns ${VAULT_NS}
kubectl get csr ${CSR_NAME} -o jsonpath='{.metadata.name}' >& /dev/null
if [[ $? -eq 0 ]]
then
    kubectl delete csr ${CSR_NAME}
fi

bootstrap_token=$(kubectl get secret ${CONSUL_RELEASE}-consul-bootstrap-acl-token -n ${CONSUL_NS} -o jsonpath='{.data.token}' | base64 -d)
consul_server_pod=$(kubectl get pods -n ${CONSUL_NS} -l release=${CONSUL_RELEASE},component=server --field-selector status.phase=Running -o jsonpath='{.items[0].metadata.name}')
kubectl exec ${consul_server_pod} -n ${CONSUL_NS} -- sh -c "export CONSUL_HTTP_TOKEN=${bootstrap_token}; consul kv delete -recurse vault/"
