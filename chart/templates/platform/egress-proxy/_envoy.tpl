{{/* The one way out to a hostname: CONNECT only, to port 443 only, to these names, every request logged; anything
     else is a 403. Names match :authority literally (exact, case-insensitive; *.suffix: its subdomains; .suffix:
     the name and its subdomains), so an IP-literal CONNECT matches no name. Carried by
     the proxy's pod template (aisolate.dev/envoy-yaml), never a ConfigMap: nobody who may write ConfigMaps rewrites it. */}}
{{- define "aisolate.envoyYaml" -}}
{{- $domains := list -}}
{{- range .Values.platform.egress.proxy.domains -}}
{{- $d := lower . -}}
{{- if hasPrefix "." $d -}}
{{- $domains = append $domains (printf "%s:443" (trimPrefix "." $d)) -}}
{{- $domains = append $domains (printf "*%s:443" $d) -}}
{{- else -}}
{{- $domains = append $domains (printf "%s:443" $d) -}}
{{- end -}}
{{- end -}}
{{- /* Resolved without the search path, in the filter's cache and the cluster's alike. */ -}}
{{- $dnsCache := dict "name" "egress" "dns_lookup_family" "V4_ONLY" "typed_dns_resolver_config" (dict "name" "envoy.network.dns_resolver.cares" "typed_config" (dict "@type" "type.googleapis.com/envoy.extensions.network.dns_resolver.cares.v3.CaresDnsResolverConfig" "dns_resolver_options" (dict "no_default_search_domain" true))) | toJson -}}
static_resources:
  listeners:
    - name: proxy
      address:
        socket_address: {address: 0.0.0.0, port_value: 3128}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: egress
                upgrade_configs:
                  - upgrade_type: CONNECT
                access_log:
                  - name: envoy.access_loggers.stdout
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
                http_filters:
                  - name: envoy.filters.http.dynamic_forward_proxy
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
                      dns_cache_config: {{ $dnsCache }}
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  virtual_hosts:
                    - name: allowed
                      domains: {{ $domains | uniq | toJson }}
                      routes:
                        - match: {connect_matcher: {}}
                          route:
                            cluster: egress
                            timeout: 0s
                            upgrade_configs:
                              - upgrade_type: CONNECT
                                connect_config: {}
                        - match: {prefix: /}
                          direct_response: {status: 403}
                    - name: refused
                      domains: ["*"]
                      routes:
                        - match: {connect_matcher: {}}
                          direct_response: {status: 403}
                        - match: {prefix: /}
                          direct_response: {status: 403}
  clusters:
    - name: egress
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.dynamic_forward_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
          dns_cache_config: {{ $dnsCache }}
{{- end -}}
