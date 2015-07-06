# Cloudify Bootstrap Local Manager plugin

Cloudify 3 plugin for bootstraping Manager with CFY and Manager Blueprint on Local Host with Docker

### Prerequisites

You'll need Cloudify CLI installed on the box where you want Manager to run: [Cloudify Installation instructions](http://getcloudify.org/guide/3.2/installation.html)

This plugin also assumes that Docker is installed and it will fail to do anything if Docker is not on the box.

        
        IMPORTAN!! This plugin doesn't try to smart and install Docker


### No-Elasticsearch


I created this plugin for a Standalone version of Elasticsearch that is why it is capable of Bootstraping Elasticsearch indexes if required.

 
### Configuration and Usage


For sample blueprint and way of using it, look in the blueprint folder.
