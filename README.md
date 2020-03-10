# Vault Operator

This repository contains the scritps and configurations by using official HashiCorp Helm chart for installing
and configuring Vault on Kubernetes. The vault-helm chart supports multiple use
cases of Vault on Kubernetes depending on the values provided.

For full documentation on the Vault Helm chart along with all the ways you can
use Vault with Kubernetes, please see the
[Vault and Kubernetes documentation](https://www.vaultproject.io/docs/platform/k8s/index.html).

## Prerequisites
To use the charts here, [Helm](https://helm.sh/) and [consul-helm](https://github.com/hashicorp/consul-helm) must be installed in your
Kubernetes cluster. Setting up Kubernetes and Helm and consul-helm and is outside the scope
of this README. Please refer to the Kubernetes and Helm documentation.

The versions required are:

  * **Helm 2.10+** - This is the earliest version of Helm tested. It is possible
    it works with earlier versions but this chart is untested for those versions.
  * **Kubernetes 1.9+** - This is the earliest version of Kubernetes tested.
    It is possible that this chart works with earlier versions but it is
    untested. Other versions verified are Kubernetes 1.10, 1.11.

## Usage

Assuming this repository was unpacked into the directory `vault-operator`, the vault cluster can
then be installed and setup directly:

    cd ./vault-operator && ./setupVaultCluster.sh

It will use vault-helm with release v0.3.3 and will setup the vault cluster in namespace `vault` 
with helm release name `vault` and will use consul with helm release name `consul` installed in namespace `consul` by default.
Please see options used in `helm-vault-values.yaml` and the many options supported in the `values.yaml`
file. These are also fully documented directly on the
[Vault website](https://www.vaultproject.io/docs/platform/k8s/helm.html).

