#include <stdio.h>                                                          //for FILE, fopen(), fgets(), and fclose()
#include <stdlib.h>
#include <string.h>                                                         //strchr(), strstr(), and snprintf()
#include <dirent.h>                                                         //opendir(), readdir(), and closedir().
#include <limits.h>

#include <cligen/cligen.h>                                                  //for Cligen definitions like cvec, cbuf, and cg_var.
#include <clixon/clixon.h>                                                  //for Clixon plugin API definitions.clixon_handle, cxobj, clixon_plugin_api, and clixon_xml_parse_string().

#define SDWAN_NS "urn:sdwan:cpe"
#define KEY_DIR  "/var/lib/clixon/local-public-keys"

static int
read_file(const char *path, char *buf, size_t buflen)
{
    FILE *fp;
    char *nl;

    fp = fopen(path, "r");
    if (fp == NULL)
        return -1;

    if (fgets(buf, buflen, fp) == NULL) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    nl = strchr(buf, '\n');
    if (nl)
        *nl = '\0';
    return 0;
}

static int
//Defines the Clixon backend state callback.
sdwan_cpe_statedata(clixon_handle h,                                                  //h        = Clixon handle                                  
                    cvec *nsc,                                                        //nsc      = namespace context
                    char *xpath,                                                      //xpath    = requested XPath filter
                    cxobj *xconfig)                                                   //xconfig  = XML tree where plugin adds state data
{
    DIR *dir;                                                                         //a directory pointer.
    struct dirent *entry;                                                             //Declares a directory entry pointer.Each entry represents one file inside the directory.
    char filepath[PATH_MAX];                                                          //Creates a buffer to store the full file path.
    char tunnel_name[64];                                                             //Creates a buffer to store the tunnel name.
    char public_key[128];                                                             //Creates a buffer to store the public key read from the file.
    char xmlbuf[2048];                                                                //Creates a buffer to store the XML string that will be returned to Clixon.
    char *dot;                                                                        //Declares a pointer used to find .pub in the filename.

    dir = opendir(KEY_DIR);
    if (dir == NULL) {
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        snprintf(tunnel_name, sizeof(tunnel_name), "%s", entry->d_name);

        dot = strstr(tunnel_name, ".pub");
        if (dot == NULL)
            continue;

        *dot = '\0';

        snprintf(filepath, sizeof(filepath), "%s/%s", KEY_DIR, entry->d_name);

        if (read_file(filepath, public_key, sizeof(public_key)) < 0)                                   //Reads the public key from the file. If reading fails, skip this file and continue with the next one.
            continue;

        snprintf(xmlbuf, sizeof(xmlbuf),                                                               //Starts building an XML string into xmlbuf
                 "<sdwan xmlns=\"%s\">"                                                                //Starts the top-level XML node.
                   "<overlay>" 
                     "<tunnel>"
                       "<name>%s</name>"
                       "<local-public-key>%s</local-public-key>"                                      //the operational leaf
                     "</tunnel>"
                   "</overlay>"
                 "</sdwan>",
                 SDWAN_NS,
                 tunnel_name,
                 public_key);

        if (clixon_xml_parse_string(xmlbuf, YB_NONE, 0, &xconfig, 0) < 0) {                          //Passes the XML string to Clixon.Clixon parses this XML and adds it into the operational-state reply.If parsing fails, the function enters the error block.
            closedir(dir);                                                                           //closedir(dir);
            return -1;
        }
    }

    closedir(dir);
    return 0;
}

static clixon_plugin_api api = {
    "callback_plugin",
    NULL,                   /* init */
    NULL,                   /* start */
    NULL,                   /* exit */
    NULL,                   /* extension */
    .ca_statedata = sdwan_cpe_statedata,
};

clixon_plugin_api *
clixon_plugin_init(clixon_handle h)
{
    return &api;
}
