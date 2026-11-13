// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"crypto"
	"encoding/base64"
	"time"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	test_common "github.com/gonewx/wicket/test/common"
	"github.com/gonewx/wicket/utils"
)

func clientValidationTestClients() []*storage_models.Client {
	disabledClient := storage_models.NewClient()
	disabledClient.ClientName = "Disabled client"
	disabledClient.ClientId = "disabled_client"
	disabledClient.Enabled = false

	secret := storage_models.NewSecret()
	secret.Value = "secret"

	disabledClient.ClientSecrets = []*storage_models.Secret{secret}

	noSecretClient := storage_models.NewClient()
	noSecretClient.ClientName = "Client with no secret set"
	noSecretClient.ClientId = "no_secret_client"
	noSecretClient.Enabled = true

	nullSecretClient := storage_models.NewClient()
	nullSecretClient.ClientName = "Client with null secret set"
	nullSecretClient.ClientId = "null_secret_client"
	nullSecretClient.Enabled = true

	secret = storage_models.NewSecret()
	secret.Value = ""

	nullSecretClient.ClientSecrets = []*storage_models.Secret{secret}

	singleSecretNoProtectionNoExpiration := storage_models.NewClient()
	singleSecretNoProtectionNoExpiration.ClientName = "Client with single secret, no protection, no expiration"
	singleSecretNoProtectionNoExpiration.ClientId = "single_secret_no_protection_no_expiration"
	singleSecretNoProtectionNoExpiration.Enabled = false

	secret = storage_models.NewSecret()
	secret.Value = "secret"

	singleSecretNoProtectionNoExpiration.ClientSecrets = []*storage_models.Secret{secret}

	certificateValid := storage_models.NewClient()
	certificateValid.ClientName = "Client with X509 Certificate"
	certificateValid.ClientId = "certificate_valid"
	certificateValid.Enabled = true

	key, _ := test_common.LoadKey()
	v, _ := key.Thumbprint(crypto.MD5)

	secret = storage_models.NewSecret()
	secret.Type = wicket.SecretTypesX509CertificateThumbprint
	secret.Value = string(v)

	certificateValid.ClientSecrets = []*storage_models.Secret{secret}

	certificateInvalid := storage_models.NewClient()
	certificateInvalid.ClientName = "Client with X509 Certificate"
	certificateInvalid.ClientId = "certificate_invalid"
	certificateInvalid.Enabled = true

	secret = storage_models.NewSecret()
	secret.Type = wicket.SecretTypesX509CertificateThumbprint
	secret.Value = "invalid"

	certificateInvalid.ClientSecrets = []*storage_models.Secret{secret}

	certificateBase64Valid := storage_models.NewClient()
	certificateBase64Valid.ClientName = "Client with Base64 encoded X509 Certificate"
	certificateBase64Valid.ClientId = "certificate_base64_valid"
	certificateBase64Valid.Enabled = true

	cert, _ := test_common.Load()

	secret = storage_models.NewSecret()
	secret.Type = wicket.SecretTypesX509CertificateBase64
	secret.Value = base64.StdEncoding.EncodeToString(cert)

	certificateBase64Valid.ClientSecrets = []*storage_models.Secret{secret}

	certificateBase64Invalid := storage_models.NewClient()
	certificateBase64Invalid.ClientName = "Client with Base64 encoded X509 Certificate"
	certificateBase64Invalid.ClientId = "certificate_base64_invalid"
	certificateBase64Invalid.Enabled = true

	secret = storage_models.NewSecret()
	secret.Type = wicket.SecretTypesX509CertificateBase64
	secret.Value = "invalid"

	certificateBase64Invalid.ClientSecrets = []*storage_models.Secret{secret}

	singleSecretHashedNoExpiration := storage_models.NewClient()
	singleSecretHashedNoExpiration.ClientName = "Client with single secret, hashed, no expiration"
	singleSecretHashedNoExpiration.ClientId = "single_secret_hashed_no_expiration"
	singleSecretHashedNoExpiration.Enabled = true

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	singleSecretHashedNoExpiration.ClientSecrets = []*storage_models.Secret{secret}

	multipleSecretsNoProtection := storage_models.NewClient()
	multipleSecretsNoProtection.ClientName = "Client with multiple secrets, no protection"
	multipleSecretsNoProtection.ClientId = "multiple_secrets_no_protection"
	multipleSecretsNoProtection.Enabled = true

	secret1 := storage_models.NewSecret()
	secret1.Value = "secret"

	secret2 := storage_models.NewSecret()
	secret2.Value = "foobar"
	secret2.Description = "some description"

	secret3 := storage_models.NewSecret()
	secret3.Value = "quux"

	secret4 := storage_models.NewSecret()
	secret4.Value = "notexpired"
	secret4.Expiration = time.Now().Add(1 * 24 * time.Hour)

	secret5 := storage_models.NewSecret()
	secret5.Value = "expired"
	secret5.Expiration = time.Now().Add(-1 * 24 * time.Hour)

	multipleSecretsNoProtection.ClientSecrets = []*storage_models.Secret{
		secret1,
		secret2,
		secret3,
		secret4,
		secret5,
	}

	multipleSecretsHashed := storage_models.NewClient()
	multipleSecretsHashed.ClientName = "Client with multiple secrets, hashed"
	multipleSecretsHashed.ClientId = "multiple_secrets_hashed"
	multipleSecretsHashed.Enabled = true

	secret1 = storage_models.NewSecret()
	secret1.Value = utils.Sha256("secret")

	secret2 = storage_models.NewSecret()
	secret2.Value = utils.Sha256("foobar")
	secret2.Description = "some description"

	secret3 = storage_models.NewSecret()
	secret3.Value = utils.Sha512("quux")

	secret4 = storage_models.NewSecret()
	secret4.Value = utils.Sha256("notexpired")
	secret4.Expiration = time.Now().Add(1 * 24 * time.Hour)

	secret5 = storage_models.NewSecret()
	secret5.Value = utils.Sha512("expired")
	secret5.Expiration = time.Now().Add(-1 * 24 * time.Hour)

	multipleSecretsHashed.ClientSecrets = []*storage_models.Secret{
		secret1,
		secret2,
		secret3,
		secret4,
		secret5,
	}

	mtlsClientInvalid := storage_models.NewClient()
	mtlsClientInvalid.ClientName = "MTLS Client with invalid secrets"
	mtlsClientInvalid.ClientId = "mtls_client_invalid"
	mtlsClientInvalid.Enabled = true

	secret1 = storage_models.NewSecret()
	secret1.Value = "CN=invalid"
	secret1.Description = "mtls.test"
	secret1.Type = wicket.SecretTypesX509CertificateName

	secret2 = storage_models.NewSecret()
	secret2.Value = "invalid"
	secret2.Description = "mtls.test"
	secret2.Type = wicket.SecretTypesX509CertificateThumbprint

	mtlsClientInvalid.ClientSecrets = []*storage_models.Secret{
		secret1,
		secret2,
	}

	mtlsClientValid := storage_models.NewClient()
	mtlsClientValid.ClientName = "MTLS Client with valid secrets"
	mtlsClientValid.ClientId = "mtls_client_valid"
	mtlsClientValid.Enabled = true

	secret1 = storage_models.NewSecret()
	secret1.Value = "CN=identityserver_testing"
	secret1.Description = "mtls.test"
	secret1.Type = wicket.SecretTypesX509CertificateName

	secret2 = storage_models.NewSecret()
	secret2.Value = "4B5FE072C7AD8A9B5DCFDD1A20608BB54DE0954F"
	secret2.Description = "mtls.test"
	secret2.Type = wicket.SecretTypesX509CertificateThumbprint

	mtlsClientValid.ClientSecrets = []*storage_models.Secret{
		secret1,
		secret2,
	}

	return []*storage_models.Client{
		disabledClient,
		noSecretClient,
		nullSecretClient,
		singleSecretNoProtectionNoExpiration,
		certificateValid,
		certificateInvalid,
		certificateBase64Valid,
		certificateBase64Invalid,
		singleSecretHashedNoExpiration,
		multipleSecretsNoProtection,
		multipleSecretsHashed,
		mtlsClientInvalid,
		mtlsClientValid,
	}
}
