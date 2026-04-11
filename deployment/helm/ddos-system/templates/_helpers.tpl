{{/*
Helpers for DDoS System Helm chart
*/}}

{{- define "ddos-system.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ddos-system.fullname" -}}
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

{{- define "ecr.registry" -}}
{{- if .Values.global }}
{{- .Values.global.ecrRepository | default (printf "%s.dkr.ecr.%s.amazonaws.com/ddos-system" .Values.global.aws.accountId .Values.global.aws.region) }}
{{- else }}
ddos-system.local
{{- end }}
{{- end }}

{{- define "service.port" -}}
{{- default 80 .Values.service.port }}
{{- end -}}
