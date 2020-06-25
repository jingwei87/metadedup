#include "CryptoPrimitive.hh"
#include "DedupCore.hh"
#include "minDedupCore.hh"
#include "server.hh"

using namespace std;

DedupCore *dedupObj;
minDedupCore *minDedupObj;

Server *server;

void usage(char *s)
{

    printf("usage: %s [metaPort] [dataPort] [kmPort]\n", s);
    printf("\t- [metaPort]: port of meta data server\n");
    printf("\t- [dataPort]: port of data server\n");
    printf("\t- [kmPort]: port of key management server\n");
}

int main(int argc, char *argv[])
{

    if(argc != 4) {
        usage(argv[0]);
        return -1;
    }

    /* enable openssl locks */
    if(!CryptoPrimitive::opensslLockSetup()) {
        printf("fail to set up OpenSSL locks\n");

        exit(1);
    }

    /* initialize objects */
    BackendStorer *recipeStorerObj = NULL;
    BackendStorer *containerStorerObj = NULL;
    dedupObj = new DedupCore("./", "meta/DedupDB", "meta/RecipeFiles", "meta/ShareContainers", recipeStorerObj,
                             containerStorerObj);
    minDedupObj = new minDedupCore("./", "meta/minDedupDB", "meta/RecipeFiles", "meta/minShareContainers",
                                   containerStorerObj);

    /* initialize server object */
    server = new Server(atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), dedupObj, minDedupObj);
    /* run server service */
    server->runReceive();

    /* openssl lock cleanup */
    CryptoPrimitive::opensslLockCleanup();

    return 0;
}
