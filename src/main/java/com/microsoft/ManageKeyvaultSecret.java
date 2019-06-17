package com.microsoft;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.arm.utils.SdkContext;
import com.microsoft.azure.credentials.ApplicationTokenCredentials;
import com.microsoft.azure.credentials.AzureTokenCredentials;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.SecretBundle;
import com.microsoft.azure.keyvault.requests.SetSecretRequest;
import com.microsoft.azure.management.keyvault.v2016_10_01.AccessPolicyEntry;
import com.microsoft.azure.management.keyvault.v2016_10_01.CertificatePermissions;
import com.microsoft.azure.management.keyvault.v2016_10_01.CreateMode;
import com.microsoft.azure.management.keyvault.v2016_10_01.KeyPermissions;
import com.microsoft.azure.management.keyvault.v2016_10_01.Permissions;
import com.microsoft.azure.management.keyvault.v2016_10_01.SecretPermissions;
import com.microsoft.azure.management.keyvault.v2016_10_01.Sku;
import com.microsoft.azure.management.keyvault.v2016_10_01.SkuName;
import com.microsoft.azure.management.keyvault.v2016_10_01.VaultPatchProperties;
import com.microsoft.azure.management.keyvault.v2016_10_01.VaultProperties;
import com.microsoft.azure.management.profile_2019_03_01_hybrid.Azure;
import com.microsoft.azure.management.resources.v2018_05_01.ResourceGroup;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;

public final class ManageKeyvaultSecret {

        final static String armEndpoint = System.getenv("ARM_ENDPOINT");
        final static String location = System.getenv("RESOURCE_LOCATION");
        final static String client = System.getenv("AZURE_CLIENT_ID");
        final static String tenant = System.getenv("AZURE_TENANT_ID");
        final static String key = System.getenv("AZURE_CERT_SECRET");
        final static String subscriptionId = System.getenv("AZURE_SUBSCRIPTION_ID");
        final static String certPath = System.getenv("AZURE_CERT_PATH");
        final static String objectId = System.getenv("AZURE_OBJECT_ID");
        final static String vaultName = SdkContext.randomResourceName("vault", 20);
        final static String rgName = SdkContext.randomResourceName("rg", 24);

        public static boolean manageSecrets(Azure azureStack, AzureEnvironment AZURE_STACK) {
                try {
                        // Create a resource group
                        ResourceGroup resourceGroup = azureStack.resourceGroups().define(rgName)
                                        .withExistingSubscription().withLocation(location).create();
                        System.out.println("Resource Group created: " + resourceGroup.name());

                        // Keyvault Certificate auth
                        KeyVaultClient kvClientCertAuth = KeyVaultCertificateAuthenticator.getAuthentication(certPath,
                                        key, client);

                        System.out.println("Creating Keyvault and secret");
                        com.microsoft.azure.management.keyvault.v2016_10_01.Vault vaultCert = createKeyVault(azureStack,
                                        AZURE_STACK.keyVaultDnsSuffix());

                        // Set secret
                        SecretBundle otherSecretBundle = kvClientCertAuth.setSecret(new SetSecretRequest.Builder(
                                        "https://" + vaultCert.properties().vaultUri(), "auth-other-sample-secret",
                                        "client is authenticated to the vault").build());
                        System.out.println(otherSecretBundle);

                        // Get secret
                        System.out.println("Getting Secret");
                        otherSecretBundle = kvClientCertAuth.getSecret("https://" + vaultCert.properties().vaultUri(),
                                        "auth-other-sample-secret");
                        System.out.println(otherSecretBundle);
                        return true;
                } catch (Exception ex) {
                        System.out.println(ex.getMessage());
                        ex.printStackTrace();
                } finally {
                        try {
                                System.out.println("Deleting Resource Group: " + rgName);
                                azureStack.resourceGroups().inner().delete(rgName);
                                System.out.println("Deleted Resource Group: " + rgName);
                        } catch (NullPointerException npe) {
                                System.out.println("Did not create any resources in Azure. No clean up is necessary");
                        } catch (Exception g) {
                                g.printStackTrace();
                        }

                }
                return false;
        }

        private static com.microsoft.azure.management.keyvault.v2016_10_01.Vault createKeyVault(Azure azure,
                        String vaultUri) throws InterruptedException {
                final UUID tenantId = UUID.fromString(tenant);

                System.out.println("Creating a new vault...");

                // Create Key permissions
                List<KeyPermissions> keys = new ArrayList<KeyPermissions>(KeyPermissions.values());
                List<CertificatePermissions> certificates = new ArrayList<CertificatePermissions>(
                                CertificatePermissions.values());

                // Create secret permissions
                List<SecretPermissions> secrets = new ArrayList<SecretPermissions>(SecretPermissions.values());
                Permissions permissions = new Permissions().withKeys(keys).withCertificates(certificates)
                                .withSecrets(secrets);

                // Create Access policy
                AccessPolicyEntry accessPolicyEntry = new AccessPolicyEntry().withObjectId(objectId)
                                .withPermissions(permissions).withTenantId(tenantId);

                List<AccessPolicyEntry> accessPolicies = new ArrayList<AccessPolicyEntry>();
                accessPolicies.add(accessPolicyEntry);

                // Set Vault properties
                Sku sku = new Sku().withName(SkuName.STANDARD);
                VaultProperties properties = new VaultProperties().withAccessPolicies(accessPolicies)
                                .withEnabledForDeployment(true).withEnabledForTemplateDeployment(true).withSku(sku)
                                .withTenantId(tenantId).withCreateMode(CreateMode.DEFAULT).withVaultUri(vaultUri);

                // Create key vault
                com.microsoft.azure.management.keyvault.v2016_10_01.Vault vault = azure.keyVaults().define(vaultName)
                                .withRegion(location).withExistingResourceGroup(rgName).withProperties(properties)
                                .create();

                VaultPatchProperties patchProperties = new VaultPatchProperties().withAccessPolicies(accessPolicies);
                vault.update().withProperties(patchProperties);
                System.out.println(vault.properties().vaultUri());
                System.out.println(vault.name());

                Thread.sleep(20000);
                return vault;
        }

        public static HashMap<String, String> getActiveDirectorySettings(String armEndpoint) {
                HashMap<String, String> adSettings = new HashMap<String, String>();

                try {
                        // create HTTP Client
                        HttpClient httpClient = HttpClientBuilder.create().build();

                        // Create new getRequest with below mentioned URL
                        HttpGet getRequest = new HttpGet(
                                        String.format("%s/metadata/endpoints?api-version=1.0", armEndpoint));

                        // Add additional header to getRequest which accepts application/xml data
                        getRequest.addHeader("accept", "application/xml");

                        // Execute request and catch response
                        HttpResponse response = httpClient.execute(getRequest);

                        // Check for HTTP response code: 200 = success
                        if (response.getStatusLine().getStatusCode() != 200) {
                                throw new RuntimeException("Failed : HTTP error code : "
                                                + response.getStatusLine().getStatusCode());
                        }
                        String responseStr = EntityUtils.toString(response.getEntity());
                        JSONObject responseJson = new JSONObject(responseStr);
                        adSettings.put("galleryEndpoint", responseJson.getString("galleryEndpoint"));
                        JSONObject authentication = (JSONObject) responseJson.get("authentication");
                        String audience = authentication.get("audiences").toString().split("\"")[1];
                        adSettings.put("login_endpoint", authentication.getString("loginEndpoint"));
                        adSettings.put("audience", audience);
                        adSettings.put("graphEndpoint", responseJson.getString("graphEndpoint"));

                } catch (ClientProtocolException cpe) {
                        cpe.printStackTrace();
                        throw new RuntimeException(cpe);
                } catch (IOException ioe) {
                        ioe.printStackTrace();
                        throw new RuntimeException(ioe);
                }
                return adSettings;
        }

        public static void main(String[] args) {
                try {
                        // =============================================================
                        // Authenticate

                        // Get Azure Stack cloud endpoints
                        final HashMap<String, String> settings = getActiveDirectorySettings(armEndpoint);

                        // Register Azure Stack cloud environment
                        AzureEnvironment AZURE_STACK = new AzureEnvironment(new HashMap<String, String>() {
                                private static final long serialVersionUID = 1L;

                                {
                                        put("managementEndpointUrl", settings.get("audience"));
                                        put("resourceManagerEndpointUrl", armEndpoint);
                                        put("galleryEndpointUrl", settings.get("galleryEndpoint"));
                                        put("activeDirectoryEndpointUrl", settings.get("login_endpoint"));
                                        put("activeDirectoryResourceId", settings.get("audience"));
                                        put("activeDirectoryGraphResourceId", settings.get("graphEndpoint"));
                                        put("storageEndpointSuffix", armEndpoint.substring(armEndpoint.indexOf('.')));
                                        put("keyVaultDnsSuffix",
                                                        ".vault" + armEndpoint.substring(armEndpoint.indexOf('.')));
                                }
                        });

                        // Get PFX cert as byte array
                        byte[] certValue = Files.readAllBytes(Paths.get(certPath));

                        // Authenticate to Azure Stack using Service Principal credentials
                        AzureTokenCredentials credentials = new ApplicationTokenCredentials(client, tenant, certValue,
                                        key, AZURE_STACK).withDefaultSubscriptionId(subscriptionId);

                        Azure azureStack = Azure.configure().withLogLevel(com.microsoft.rest.LogLevel.BODY_AND_HEADERS)
                                        .authenticate(credentials, credentials.defaultSubscriptionId());

                        // Create Keyvalut and manage secrets
                        manageSecrets(azureStack, AZURE_STACK);
                } catch (Exception e) {
                        System.out.println(e.getMessage());
                        e.printStackTrace();
                }
        }

        private ManageKeyvaultSecret() {
        }
}
