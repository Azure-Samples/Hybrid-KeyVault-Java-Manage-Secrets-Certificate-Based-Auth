---
services: Azure-Stack
platforms: java
author: viananth
---

# Hybrid-KeyVault-Java-Manage-Secrets-Certificate-Based-Auth

This sample uses certificate based service principal authentication to work with Keyvaults.

  Azure Stack sample for managing Keyvaults -
   - Create a Keyvault using cert based authentication
   - Create a secret inside the keyvault
   - Get the secret
   - Delete the Resource Group.


## Running this Sample ##

To run this sample:

1. Clone the repository using the following command:

    git clone https://github.com/Azure-Samples/Hybrid-KeyVault-Java-Manage-Secrets-Certificate-Based-Auth.git

2. Create an Azure service principal and assign a role to access the subscription. For instructions on creating a service principal, see [Use Azure PowerShell to create a service principal with a certificate](https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-create-service-principals).

3. Export the service principal certificate as a pfx file.

4. Set the following required environment variable values:

    * AZURE_TENANT_ID

    * AZURE_CLIENT_ID

    * AZURE_CERT_SECRET
    
    * AZURE_CERT_PATH

    * AZURE_SUBSCRIPTION_ID

    * ARM_ENDPOINT

    * RESOURCE_LOCATION

5. Change directory to Hybrid sample:
    
    * cd Hybrid-KeyVault-Java-Manage-Secrets-Certificate-Based-Auth

6. Run the sample:
    * mvn clean compile exec:java

## More information ##

[http://azure.com/java](http://azure.com/java)


---

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.