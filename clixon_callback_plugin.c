#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>

#include <cligen/cligen.h>
#include <clixon/clixon.h>

#define SDWAN_NS "urn:example:sdwan-cpe"
#define KEY_DIR  "/var/lib/clixon/local-public-keys"

static int
read_first_line(const char *path, char *buf, size_t buflen)
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
sdwan_cpe_statedata(clixon_handle h,
                    cvec *nsc,
                    char *xpath,
                    cxobj *xconfig)
{
    DIR *dir;
    struct dirent *entry;
    char filepath[PATH_MAX];
    char tunnel_name[256];
    char public_key[512];
    char xmlbuf[2048];
    char *dot;

    dir = opendir(KEY_DIR);
    if (dir == NULL) {
        /*
         * No key directory yet. This is not fatal.
         * Just return no operational key state.
         */
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        snprintf(tunnel_name, sizeof(tunnel_name), "%s", entry->d_name);

        dot = strstr(tunnel_name, ".pub");
        if (dot == NULL)
            continue;

        *dot = '\0';

        snprintf(filepath, sizeof(filepath), "%s/%s", KEY_DIR, entry->d_name);

        if (read_first_line(filepath, public_key, sizeof(public_key)) < 0)
            continue;

        /*
         * Return full path down to the config false leaf.
         * The list key <name> is included so Clixon can attach the
         * state leaf to the correct tunnel list entry.
         */
        snprintf(xmlbuf, sizeof(xmlbuf),
                 "<sdwan xmlns=\"%s\">"
                   "<overlay>"
                     "<tunnel>"
                       "<name>%s</name>"
                       "<local-public-key>%s</local-public-key>"
                     "</tunnel>"
                   "</overlay>"
                 "</sdwan>",
                 SDWAN_NS,
                 tunnel_name,
                 public_key);

        if (clixon_xml_parse_string(xmlbuf, YB_NONE, 0, &xconfig, 0) < 0) {
            closedir(dir);
            return -1;
        }
    }

    closedir(dir);
    return 0;
}

static clixon_plugin_api api = {
    "sdwan-cpe-state",
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
