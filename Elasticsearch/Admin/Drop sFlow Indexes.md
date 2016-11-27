# Dropping sFlow Indexes
The following command deletes all sFlow indexes:
```
curl -XDELETE http://localhost:9200/sflow*?pretty
```

**WARNING**: This cannot be undone, all sFlow indexes will be removed.

### Copyright (c) 2016, Manito Networks, LLC
### All rights reserved.