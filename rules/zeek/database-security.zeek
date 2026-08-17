# =============================================================================
# Zeek Signatures — database-security
# Total rules: 30
# =============================================================================

signature ZK-DBPG001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /postgresql|privilege-escalation/
	event "Detect_PostgreSQL_—_Privilege_Escalation_via_SE"
}

signature ZK-DBPG002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /postgresql|data-exfiltration/
	event "Detect_PostgreSQL_—_pg_dump_Data_Exfiltration"
}

signature ZK-DBPG003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /postgresql|rls-bypass/
	event "Detect_PostgreSQL_—_Row-Level_Security_Bypass"
}

signature ZK-DBMY001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /mysql|sql-injection/
	event "Detect_MySQL_—_UNION-Based_SQL_Injection"
}

signature ZK-DBMY002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /mysql|default-account/
	event "Detect_MySQL_—_Root_Account_Remote_Login"
}

signature ZK-DBMSS001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /sqlserver|command-execution/
	event "Detect_SQL_Server_—_xp_cmdshell_Execution"
}

signature ZK-DBMSS002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /sqlserver|login-anomaly/
	event "Detect_SQL_Server_—_SUSPENDED_Login_State_Anoma"
}

signature ZK-DBORA001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /oracle|privilege-escalation/
	event "Detect_Oracle_—_DBA_Privilege_Escalation"
}

signature ZK-DBSQLITE001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /sqlite|file-access/
	event "Detect_SQLite_—_Direct_File_Access_from_Web"
}

signature ZK-DBMONGO001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /mongodb|nosql-injection/
	event "Detect_MongoDB_—_NoSQL_Injection_via_$where"
}

signature ZK-DBMONGO002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /mongodb|default-account/
	event "Detect_MongoDB_—_admin_Database_Unauthorized_Ac"
}

signature ZK-DBDYNAMO001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /dynamodb|data-exfiltration/
	event "Detect_DynamoDB_—_Excessive_Scan_Operations"
}

signature ZK-DBCASS001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /cassandra|privilege-escalation/
	event "Detect_Cassandra_—_Unauthorized_CQL_Command_Exe"
}

signature ZK-DBCOUCH001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /couchdb|default-account/
	event "Detect_CouchDB_—_Admin_Party_Mode"
}

signature ZK-DBFIRE001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /firestore|misconfiguration/
	event "Detect_Firestore_—_Overly_Permissive_Security_R"
}

signature ZK-DBNEO4J001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /neo4j|cypher-injection/
	event "Detect_Neo4j_—_Cypher_Injection_Attack"
}

signature ZK-DBARANGO001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /arangodb|aql-injection/
	event "Detect_ArangoDB_—_AQL_Injection_Detection"
}

signature ZK-DBNEPTUNE001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /neptune|graph-injection/
	event "Detect_Neptune_—_Gremlin/SPARQL_Injection"
}

signature ZK-DBINFLUX001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /influxdb|data-destruction/
	event "Detect_InfluxDB_—_Unauthorized_Data_Deletion"
}

signature ZK-DBTSCALE001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /timescaledb|data-exfiltration/
	event "Detect_TimescaleDB_—_Hypertable_Data_Exfiltrati"
}

signature ZK-DBPROM001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prometheus|information-disclosure/
	event "Detect_Prometheus_—_Unauthorized_Metric_Scrapin"
}

signature ZK-DBPINE001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pinecone|vector/
	event "Detect_Pinecone_—_Namespace_Isolation_Bypass"
}

signature ZK-DBWEAV001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /weaviate|vector/
	event "Detect_Weaviate_—_Tenant_Data_Isolation_Failure"
}

signature ZK-DBMILV001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /milvus|vector/
	event "Detect_Milvus_—_Collection-Level_Access_Bypass"
}

signature ZK-DBCHROMA001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /chromadb|vector/
	event "Detect_ChromaDB_—_Embedding_Poisoning_Detection"
}

signature ZK-DBQDRANT001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /qdrant|vector/
	event "Detect_Qdrant_—_Payload_Filter_Injection"
}

signature ZK-DBREDIS001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /redis|credential-exposure/
	event "Detect_Redis_—_CONFIG_GET_Credential_Exposure"
}

signature ZK-DBREDIS002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /redis|data-destruction/
	event "Detect_Redis_—_FLUSHALL/FLUSHDB_Data_Destructio"
}

signature ZK-DBMEMC001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /memcached|amplification/
	event "Detect_Memcached_—_Amplification_Attack"
}

signature ZK-DBHBASE001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /hbase|acl-modification/
	event "Detect_HBase_—_Unauthorized_ACL_Modification"
}
