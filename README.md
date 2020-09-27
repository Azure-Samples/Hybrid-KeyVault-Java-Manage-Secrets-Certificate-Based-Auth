---
page_type: sample
languages:
- java
products:
- azure
description: "This sample uses certificate based service principal authentication to work with Keyvaults."
urlFragment: Hybrid-KeyVault-Java-Manage-Secrets-Certificate-Based-Auth
---


# Hybrid-KeyVault-Java-Manage-Secrets-Certificate-Based-Auth

## This sample shows how to do the following operations of Key Vault with Key Vault SDK

* Create a Key Vault using certificate based authentication
* Create a secret inside the Key Vault
* Get the secret
* Delete the Resource Group

## Running this Sample

To run this sample:

1. Clone the repository using the following command:

    git clone https://github.com/Azure-Samples/Hybrid-KeyVault-Java-Manage-Secrets-Certificate-Based-Auth.git

2. Create an Azure service principal and assign a role to access the subscription. For instructions on creating a service principal, see [Use Azure PowerShell to create a service principal with a certificate](https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-create-service-principals).

3. Export the service principal certificate as a pfx file.

4. Set the following required environment variable values:

    - AZURE_TENANT_ID
    - AZURE_CLIENT_ID
    - AZURE_OBJECT_ID (To set access permissions for KeyVault. You can retrieve this value from the output during Service Principal Creation)
    - AZURE_CERT_SECRET
    - AZURE_CERT_PATH
    - AZURE_SUBSCRIPTION_ID
    - ARM_ENDPOINT
    - RESOURCE_LOCATION

5. Change directory to Hybrid sample:
    - cd Hybrid-KeyVault-Java-Manage-Secrets-Certificate-Based-Auth

6. Run the sample:
    - mvn clean compile exec:java

## Use latest Key Vault SDK

The Key Vault secrets SDK here is **com.azure:azure-security-keyvault-secrets**, if you are using the [latest](https://search.maven.org/artifact/com.azure/azure-security-keyvault-secrets) version of the Key Vault SDK package, please refer to the following examples:

* [IdentityReadmeSamples.java](https://github.com/Azure/azure-sdk-for-java/blob/master/sdk/keyvault/azure-security-keyvault-secrets/src/samples/java/com/azure/security/keyvault/secrets/IdentityReadmeSamples.java) shows multiple ways to authenticate the Key Vault client via DefaultAzureCredential, device code, client secret or certificate in addition to others.

* [HelloWorld.java](https://github.com/Azure/azure-sdk-for-java/blob/master/sdk/keyvault/azure-security-keyvault-secrets/src/samples/java/com/azure/security/keyvault/secrets/HelloWorld.java) - Examples for common Key Vault tasks:

    * Create a secret inside the Key Vault
    * Get the secret

## More information

https://azure.com/java

---

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
