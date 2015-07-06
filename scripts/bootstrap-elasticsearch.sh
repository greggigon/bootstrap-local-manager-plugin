#!/bin/sh


curl --retry 5 --retry-delay 3 -XDELETE http://localhost:9200/cloudify_events/
echo "creating events index..."
curl --retry 5 --retry-delay 3 -XPUT http://localhost:9200/cloudify_events -d '{"settings": {"analysis": {"analyzer": {"default": {"tokenizer": "whitespace"}}}}}'
echo "deleting index if exists..."
curl --retry 5 --retry-delay 3 -XDELETE http://localhost:9200/cloudify_storage
echo "creating index..."
curl --retry 5 --retry-delay 3 -XPUT http://localhost:9200/cloudify_storage -d '{"settings": {"analysis": {"analyzer": {"default": {"tokenizer": "whitespace"}}}}}'
echo "creating blueprint mapping..."
curl --retry 5 --retry-delay 3 -XPUT http://localhost:9200/cloudify_storage/blueprint/_mapping -d '{"blueprint": {"properties": {"plan": {"enabled": false}}}}'
echo "creating deployment mapping..."
curl --retry 5 --retry-delay 3 -XPUT http://localhost:9200/cloudify_storage/deployment/_mapping -d '{"deployment": {"properties": {"workflows": {"enabled": false}, "inputs": {"enabled": false}, "policy_type": {"enabled": false}, "policy_triggers": {"enabled": false}, "groups": {"enabled": false}, "outputs": {"enabled": false}}}}'
echo "creating node mapping..."
curl --retry 5 --retry-delay 3 -XPUT http://localhost:9200/cloudify_storage/node/_mapping -d '{ "node": { "_id": { "path": "id" }, "properties": { "types": { "type": "string", "index_name": "type" }, "properties": { "enabled": false }, "operations": { "enabled": false }, "relationships": { "enabled": false } } } }'
echo "creating node-instance mapping..." && \
curl --retry 5 --retry-delay 3 -XPUT http://localhost:9200/cloudify_storage/node_instance/_mapping -d '{ "node_instance": { "_id": { "path": "id" }, "properties": { "runtime_properties": { "enabled": false } } } }' && \
echo "creating deployment-modifications mapping..." && \
curl --retry 5 --retry-delay 3 -XPUT http://localhost:9200/cloudify_storage/deployment_modification/_mapping -d '{ "deployment_modification": { "_id": { "path": "id" }, "properties": { "modified_nodes": { "enabled": false }, "node_instances": { "enabled": false }, "context": { "enabled": false } } } }' && \
echo "printing mappings..." && \
curl --retry 5 --retry-delay 3 -XGET http://localhost:9200/cloudify_storage/_mapping?pretty=1 && \

echo "printing mappings..."
curl --retry 5 --retry-delay 3 -XGET http://localhost:9200/cloudify_storage/_mapping?pretty=1