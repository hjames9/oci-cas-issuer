# oci-cas-issuer

`oci-cas-issuer` is a cert-manager external issuer for Oracle Cloud Infrastructure private Certificate Authorities. It watches approved cert-manager `CertificateRequest` resources, sends the embedded CSR to OCI Certificates Management, and writes the signed certificate chain back to request status.

This is not a DNS-01 ACME webhook. The issuer CA is an OCI private CA.

## Install

```bash
helm install oci-cas-issuer charts/oci-cas-issuer \
  --namespace oci-cas-issuer \
  --create-namespace
```

Supported cert-manager range: v1.15 and newer. The current module resolves against cert-manager v1.18.x through `issuer-lib`.

## Examples

```yaml
apiVersion: cas.oci-issuer.cert-manager.io/v1alpha1
kind: OCIClusterIssuer
metadata:
  name: oci-private-ca
spec:
  certificateAuthorityId: ocid1.certificateauthority.oc1.iad.example
  compartmentId: ocid1.compartment.oc1..example
  region: us-ashburn-1
  auth:
    type: workloadIdentity
```

For API key auth with a cluster-scoped issuer, put the Secret in the controller cluster resource namespace. The Helm chart defaults that namespace to the release namespace, usually `oci-cas-issuer`.

```yaml
apiVersion: cas.oci-issuer.cert-manager.io/v1alpha1
kind: OCIClusterIssuer
metadata:
  name: oci-private-ca-api-key
spec:
  certificateAuthorityId: ocid1.certificateauthority.oc1.iad.example
  compartmentId: ocid1.compartment.oc1..example
  region: us-ashburn-1
  auth:
    type: apiKey
    apiKeySecretRef:
      name: oci-api-key
```

A namespaced `OCIIssuer` uses the same spec shape, but the referenced Secret must be in the issuer namespace:

```yaml
apiVersion: cas.oci-issuer.cert-manager.io/v1alpha1
kind: OCIIssuer
metadata:
  name: oci-private-ca
  namespace: app
spec:
  certificateAuthorityId: ocid1.certificateauthority.oc1.iad.example
  compartmentId: ocid1.compartment.oc1..example
  region: us-ashburn-1
  auth:
    type: apiKey
    apiKeySecretRef:
      name: oci-api-key
```

API key Secrets can use split fields:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: oci-api-key
  # Use the OCIIssuer namespace, or the controller cluster resource namespace for OCIClusterIssuer.
  namespace: app
type: Opaque
stringData:
  tenancy: ocid1.tenancy.oc1..example
  user: ocid1.user.oc1..example
  region: us-ashburn-1
  fingerprint: 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff
  privateKey: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
  passphrase: optional-private-key-passphrase
```

Or OCI CLI-style fields:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: oci-api-key
  # Use the OCIIssuer namespace, or the controller cluster resource namespace for OCIClusterIssuer.
  namespace: app
type: Opaque
stringData:
  config: |
    [DEFAULT]
    tenancy=ocid1.tenancy.oc1..example
    user=ocid1.user.oc1..example
    region=us-ashburn-1
    fingerprint=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff
    key_file=/ignored/by/the/controller
  key.pem: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
```

Certificate example with the cert-manager fields this issuer consumes from the generated CSR and request metadata:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: app-tls
  namespace: app
spec:
  secretName: app-tls
  duration: 24h
  renewBefore: 8h
  privateKey:
    algorithm: RSA
    size: 2048
    rotationPolicy: Always
  usages:
    - digital signature
    - key encipherment
    - server auth
    - client auth
  commonName: app.example.com
  subject:
    organizations:
      - Example Inc
    organizationalUnits:
      - Platform
    countries:
      - US
    localities:
      - Atlanta
    provinces:
      - Georgia
    streetAddresses:
      - 123 Main St
    postalCodes:
      - "30301"
    serialNumber: app-001
  dnsNames:
    - app.example.com
    - www.app.example.com
  ipAddresses:
    - 10.0.0.10
  uris:
    - spiffe://example.com/app
  emailAddresses:
    - admin@example.com
  issuerRef:
    group: cas.oci-issuer.cert-manager.io
    kind: OCIIssuer
    name: oci-private-ca
```

To use the cluster-scoped issuer instead, set `issuerRef.kind: OCIClusterIssuer` and `issuerRef.name: oci-private-ca`.

For external ClusterIssuers, the `cert-manager.io/cluster-issuer` Ingress annotation does not select custom issuer groups. Use `cert-manager.io/issuer` plus a full `issuerRef` in Certificate resources when possible.

The Helm chart grants cert-manager's built-in approver permission to approve `CertificateRequest` resources for `ociissuers.cas.oci-issuer.cert-manager.io/*` and `ociclusterissuers.cas.oci-issuer.cert-manager.io/*`. If cert-manager runs with a non-default ServiceAccount, set `certManager.approver.serviceAccount` in chart values.

OCI's external CSR signing path currently rejects CSRs with an empty subject common name. Set `spec.commonName` on `Certificate` resources as well as the appropriate SAN fields.

## Auth

`workloadIdentity` is the default and recommended mode for enhanced OKE clusters. The controller supplies the OCI Go SDK workload identity defaults from the issuer `region`.

Basic OKE clusters, including Always Free tier clusters, do not support the OKE Workload Identity token endpoint used by the OCI SDK. Use `apiKey` or `instancePrincipal` for those clusters.

`instancePrincipal` is available for node/instance based deployments. `apiKey` reads a Kubernetes Secret with either split fields:

```text
tenancy
user
region
fingerprint
privateKey
passphrase optional
```

or OCI CLI-style fields:

```text
config
key.pem
```

For a namespaced `OCIIssuer`, the Secret is in the issuer namespace. For `OCIClusterIssuer`, the Secret is in the controller `--cluster-resource-namespace`, which the Helm chart defaults to the release namespace.

## OCI IAM

Example policies for OKE Workload Identity through a dynamic group:

```text
Allow dynamic-group <issuer-dynamic-group> to read certificate-authorities in compartment <ca-compartment>
Allow dynamic-group <issuer-dynamic-group> to use certificate-authority-delegates in compartment <ca-compartment>
Allow dynamic-group <issuer-dynamic-group> to manage leaf-certificate-family in compartment <certificate-compartment>
Allow dynamic-group <issuer-dynamic-group> to read leaf-certificate-bundles in compartment <certificate-compartment>
```

For API key auth, replace `dynamic-group` with `group` and grant the group containing the OCI user.

## OCI Resource Cleanup

OCI creates a managed Certificate resource for each external CSR issuance. The controller names resources deterministically from the `CertificateRequest` UID and schedules deletion after the certificate bundle is retrieved.

The issuer does not expose `certificateProfileType`; OCI's external CSR signing config does not support that field. Certificate profile behavior is controlled by the OCI CA and signing policy.
