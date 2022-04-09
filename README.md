# cpiapi package

Package to GET data-sets from the Cisco Prime Infastructure GET APIs. Includes:
- **Cpi** class defines a CPI server instance
    - **Cpi.Reader** creates a Generator which yields each item from Pager-managed
      GETs of the API. Supports filtering, paging, rate-limiting,
      and predefined or custom Pagers.
- **Cache** class defines a ~/cache cache of recently read CPI API data.
    - **Cache.Reader** creates a Generator which yields each item from the cache
or write-through to cache from Cpi.Reader
- **Catalogs** each entry in the {archive, production, real-time, test} catalogs
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
- **Logging**
    - **logErr**`(*s, start:str='\n', end:str='', **kwargs)`  
      log join(timestamp and s) via email (unix) or print(**kwargs) (Windows)  
      -`logErr.logSubject = {the subject}`  
      -`logErr.logToAddr = [email addresses]`
- **Time conversion** function for handling CPI's time formats presented in the
enterprise's home time zone
    - **anyToSecs**`(t, offset:float=0.0) -> float`  
      Converts milliseconds:int, seconds:float, or ISO datetime:str to seconds:float.
    - **millisToSecs**`(millis:int, timeDelta:float=0) -> float`  
    - **secsToMillis**`(t:float, timeDelta:float=0.0) -> int`  
      Convert to/from epochMilliseconds on foreign system from/to epochSeconds on local system
      with adjustment for local time ahead of foreign time by timeDelta seconds
    - **strfTime**`(t, millis:bool=False) -> str`  
      Format epochMillis:int or epochSeconds:float to configured **home_zone** 
      timezone
    - **strpSecs**`(s:str) -> float ` 
    Parse ISO time text to UTC epochSeconds:float.
