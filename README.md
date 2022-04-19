# What this does

The psachecker is a tool that allows you to assess a workload/all workloads in a namespace
and based on their security requirements decide what should be the lowest possible PodSecurity
privilege level that would still keep them running.

## Compiling and usage

To compile the binary, run `make build` in the repo namespace. You can then install it to
your $GOBIN by running `make install` or use it directly as `./kubectl-psachecker`

### Usage

`./kubectl-psachecker inspect-workloads -f <workload_manifest_paht> [-f <workload_manifest_path> ...] [opts]`

Returns the restrictive level for workloads present in the files specified by the `-f` flag (can be set multiple times).

`./kubectl-psachecker inspect-cluster [--updates-only]`

Returns the restrictive level for all the namespaces in the cluster.

## The state of this repository

This is an experimental repository. Bug reports and feature requests are appreciated.

## TODO
- allow setting/discovering the current cluster PSa configuration
- assess the whole cluster in order to decide the default config
    - allow setting desired config levels and then assess which namespaces would have to set
      less restrictive labels in order for the current workloads to still run
