{{- define "mcp-auth-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "mcp-auth-proxy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "mcp-auth-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "mcp-auth-proxy.labels" -}}
helm.sh/chart: {{ include "mcp-auth-proxy.chart" . }}
{{ include "mcp-auth-proxy.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "mcp-auth-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mcp-auth-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "mcp-auth-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "mcp-auth-proxy.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
The proxy configuration as the YAML document MCP_PROXY_CONFIG points at.
Secrets (the ntfy topic) are deliberately excluded; they come from a Secret.
*/}}
{{- define "mcp-auth-proxy.configYAML" -}}
base_url: {{ required "config.baseURL is required: approve/deny URLs and the MCP URL are built from it" .Values.config.baseURL | quote }}
listen_addr: {{ .Values.config.listenAddr | quote }}
state_dir: /data
session_ttl: {{ .Values.config.sessionTTL | quote }}
upstreams: {{ .Values.config.upstreams | toJson | quote }}
oauth:
  clients: {{ .Values.config.oauthClients | toJson | quote }}
ntfy:
  enabled: {{ .Values.ntfy.enabled | quote }}
  url: {{ .Values.ntfy.url | quote }}
{{- end }}
