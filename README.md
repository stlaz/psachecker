# What this does

The psachecker is a tool that allows you to assess a workload/all workloads in a namespace
and based on their security requirements decide what should be the lowest possible PodSecurity
privilege level that would still keep them running.

## Ideas to implement
- assess the whole cluster in order to decide the default config
    - allow setting desired config levels and then assess which namespaces would have to set
      less restrictive labels in order for the current workloads to still run
