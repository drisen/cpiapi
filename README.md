# cpi Package

Package to GET data-sets from Cisco Prime Infastructure APIs. Includes:
- **Cache** class for access to the CPI API data through a local file-system cache
    - **Cache.Reader** Iterable which returns each item from cache or Cpi.Reader
- **Cpi** class defines a CPI server instance
    - **Cpi.Reader** Iterable which returns each item from Pager-managed
      GETs of the API
- **Catalogs** {archive, production, real-time, test} define a relational
  view of the response
  from current and past versions of each GET API. Also define each Enum and
  each supported type.
- **classes** to define a relational view in a catalog of an API's response data
    - **Named** base class to define the name
    - **SubTable(Nameable)** class of typed fields and indices for a relational
      view of a table. Utility methods to:
      - output SQL/Hive/StorageDescriptors;
      - audit actual API response data fields, types, and values against
        the Catalog definition.
    - **Table(subTable)** class for an API version, URL, polling/paging
      parameters defining a view of an API,
  with subtable and possibly nested SubTables.
    - **Pager(Named)** class for default and customized CPI paging to
      implement the semantics required for periodically polled, as-needed
      rolling historical, and other collection approaches.
- **record Generators** to present a joined view of data retrieved from several APIs  
