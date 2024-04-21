# cpiapi package

Package to GET data-sets from the Cisco Prime Infastructure GET APIs. Includes:
- **Cpi** class defines a CPI server instance
    - **Cpi.Reader** creates a Generator which yields each item from Pager-managed
      GETs of the API. Supports filtering, paging, rate-limiting,
      and predefined or custom Pagers.
- **Cache** class manages a cache (by default in ~/cache) of recently read CPI API data.
    - **Cache.Reader** creates a Generator which yields each item from the cache
or write-through to cache from Cpi.Reader
- **Catalogs:** each entry in the {archive, production, real-time, test} catalogs
defines a relational view of the response
  from current or past version of each GET API. The catalogs also define each Enum and
  each supported type.
- **classes** to define a relational view in a catalog of an API's response data
    - **Named** base class to define the name
    - **SubTable(Nameable)** class of typed fields and indices for a relational
      view of a table. Utility methods to:
      - output SQL/Hive/StorageDescriptors;
      - audit actual API response data fields, types, and values against
        the Catalog definition.
    - **Table(SubTable)** class for an API version, URL, polling/paging
      parameters defining a view of an API, with SubTable and possibly nested SubTables.
    - **Pager(Named)** class for CPI API paging to
      implement the semantics required for periodically polled, as-needed
      rolling historical, and other collection approaches.
- **record Generators** to present a joined view of data retrieved from several APIs  

