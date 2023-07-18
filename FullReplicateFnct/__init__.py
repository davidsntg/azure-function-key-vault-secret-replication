import logging
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import ResourceNotFoundError
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    # Configuration parameters
    src_key_vault_name = req.params.get('src_key_vault_name')
    if not src_key_vault_name:
        return func.HttpResponse(f"Please pass a source key vault name on the query string or in the request body")
    src_key_vault_url = f"https://{src_key_vault_name}.vault.azure.net/"

    # Authenticate to Azure using Managed Identity
    credential = DefaultAzureCredential()

    #############################################################
    # Get Destination key vault names from the Source Key Vault #
    #############################################################
    
    resource_graph_client = ResourceGraphClient(credential)

    query = """
    Resources
    | where type == 'microsoft.keyvault/vaults'
    | where name == '{0}'
    | project tags.dst_key_vault_names""".format(src_key_vault_name)

    request = QueryRequest(query=query)
    response = resource_graph_client.resources(request)

    try:
        dst_key_vault_names = response.data[0]['tags_dst_key_vault_names'].split(',')
    except:
        logging.info(f"Key Vault {src_key_vault_name} doesn't exist or doesn't have the tag 'dst_key_vault_names'.")
        return func.HttpResponse(f"Key Vault {src_key_vault_name} doesn't exist or doesn't have the tag 'dst_key_vault_names'.")

    logging.info(f"Destination Key Vaults: : {dst_key_vault_names}")

    ##################################################################
    # Copy secrets from Source Key Vault to destination Key vault(s) #
    ##################################################################
    
    src_key_vault_secret_client = SecretClient(vault_url=src_key_vault_url, credential=credential)

    # Get all secrets in the source key vault
    for src_secret_properties in src_key_vault_secret_client.list_properties_of_secrets():
        if not src_secret_properties.enabled:
            logging.info(f"Secret {src_secret_properties.name} is disabled. Skipping creation / update of secret.")
            continue
        
        src_secret_value = src_key_vault_secret_client.get_secret(src_secret_properties.name).value

        # Copy secret to destination key vaults
        for dst_key_vault_name in dst_key_vault_names:
            dst_key_vault_url = f"https://{dst_key_vault_name}.vault.azure.net/"
            dst_key_vault_secret_client = SecretClient(vault_url=dst_key_vault_url, credential=credential)

            try:
                # Get secret value and properties in the destination key vault
                dst_secret = dst_key_vault_secret_client.get_secret(src_secret_properties.name)
                dst_secret_value = dst_secret.value
                dst_secret_properties = dst_secret.properties

                # If src & dst secret have the same value, tags, enabled, activation date, expiration date, and content type, skip creation / update of secret
                if src_secret_value == dst_secret_value and src_secret_properties.tags == dst_secret_properties.tags and src_secret_properties.enabled == dst_secret_properties.enabled and src_secret_properties.not_before == dst_secret_properties.not_before and src_secret_properties.expires_on == dst_secret_properties.expires_on and src_secret_properties.content_type == dst_secret_properties.content_type:
                    logging.info(f"Secret {src_secret_properties.name} already exists in {dst_key_vault_name} with the same value and properties. Skipping creation / update of secret.")
                    continue

                # Secret exists with different properties in the destination Key Vault - Update secret
                dst_key_vault_secret_client.set_secret(
                    src_secret_properties.name, 
                    src_secret_value, 
                    tags=src_secret_properties.tags, 
                    enabled=src_secret_properties.enabled, 
                    not_before=src_secret_properties.not_before, 
                    expires_on=src_secret_properties.expires_on, 
                    content_type=src_secret_properties.content_type
                )
                logging.info(f"Secret {src_secret_properties.name} updated in {dst_key_vault_name}.")

            except ResourceNotFoundError:
                # Secret does not exist in the destination Key Vault - Create secret
                dst_key_vault_secret_client.set_secret(
                    src_secret_properties.name, 
                    src_secret_value, 
                    tags=src_secret_properties.tags, 
                    enabled=src_secret_properties.enabled, 
                    not_before=src_secret_properties.not_before, 
                    expires_on=src_secret_properties.expires_on, 
                    content_type=src_secret_properties.content_type
                )
                logging.info(f"Secret {src_secret_properties.name} created in {dst_key_vault_name}.")

            except Exception as e:
                logging.error(f"Error: {e}")
                return func.HttpResponse(f"Error: {e}", status_code=500)

    return func.HttpResponse(f"Copy secrets from source key vault to destination key vaults {dst_key_vault_names} completed successfully.")
