# Security policy

AIsolate's job is to keep a model from seeing or returning what the asking user may not see. This chart
installs the pods that enforce that and the policies that isolate them; a render that weakens either is a
vulnerability, whatever the component. Where each guarantee is enforced: AIsolate's
[security documentation](https://github.com/reportix/aisolate/blob/main/docs/security.md).

## What counts

- A NetworkPolicy that opens more than the component's peers: a pod other than the backend reaching the
  backend's database, a discovery pod or a tool server answering another pod, egress to an address no value
  names, or the egress proxy reaching more than the hostnames it is given.
- A pod that does not run restricted on a read-only root, or an image not pinned by digest while `allowTags`
  is unset.
- A generated Secret (the database password, the audit ingest key, the credentials key) handed to a pod it is
  not meant for, or rendered where a reader of ConfigMaps can see it; the controller's settings or the proxy's
  configuration in a ConfigMap.
- A route from outside the namespace to a port the design keeps inside it: the backend's ingest port, the
  management port, a discovery or tool server pod reached around the ingress controller.
- A Role granting a component more than it uses.
- A rendered object that makes the controller's airlock and tool server pods less isolated than the chart's own.

## Reporting

Do not open a public issue. Report privately through a confidential issue in this project's issue tracker
(tick *Confidential*) or security@reportix.com. Include the chart version, the values (without their secrets)
and the rendered object that shows the problem; a failing render invariant is the best report. We confirm
receipt, keep you informed while we fix it, and credit you in the fix unless you prefer otherwise.

## Supported versions

`main` and the latest release.
