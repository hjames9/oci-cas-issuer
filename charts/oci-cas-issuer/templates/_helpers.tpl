{{- define "oci-cas-issuer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "oci-cas-issuer.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "oci-cas-issuer.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "oci-cas-issuer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "oci-cas-issuer.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
