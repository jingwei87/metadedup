#ifndef __DATASTRUCT_HH__
#define __DATASTRUCT_HH__

/*macros for LevelDB option settings*/
#define MEM_TABLE_SIZE (16 << 20)
#define BLOCK_CACHE_SIZE (32 << 20)
#define BLOOM_FILTER_KEY_BITS 10

/*macro for the name size of internal files (recipe  or container files)*/
#define INTERNAL_FILE_NAME_SIZE 16

/*macros for inodeType*/
#define DIR_TYPE 0
#define FILE_TYPE 1

/*macros for per-user buffer*/
#define RECIPE_BUFFER_SIZE (4 << 20) // size: 4MB
#define CONTAINER_BUFFER_SIZE (4 << 20) // size: 4MB
#define MAX_BUFFER_WAIT_SECS 18

/*macro for fingerprint size with the use of SHA-256 CryptoPrimitive instance*/
#define FP_SIZE 32
#define HASH_SIZE 32

/*macro for key and key size*/
#define KEY_SIZE (FP_SIZE + 1)
#define MAX_VALUE_SIZE (FP_SIZE + 1)

/*macro for share file buffer size*/
#define SHARE_FILE_BUFFER_SIZE (4 << 20) // size: 4MB

/*macro for the number of cached share containers*/
#define NUM_OF_CACHED_CONTAINERS 4

/* downloader ringbuffer data max size */
// META_BUFFER supports up to 16MB segment size
#define RING_BUFFER_DATA_SIZE (16 * 1024) // size: 16KB
#define RING_BUFFER_META_SIZE (1250 * 1024) // size: 1250KB

#define END_DOWNLOAD_INDICATOR (-12)
#define NO_RECIPE_STORED (-11)
#define FILE_RECIPE_SUCCESS (-111)
#define NO_DATA_CHUNKS_FOUND (-6)
#define END_OF_DATA_CHUNKS (-51)

/* the size of metalist buffer */
#define METALIST_BUFFER_SIZE (100 << 20) // size: 100MB
/* the indicator of sending meta_list back to client */
#define SEND_META_LIST (1001)

/* the indicator of sending meta_list back to client */
#define METACORE_NOT_END (-707)
#define METACORE_END (707)

/* the indicator: the 4-th share is stored in this server and this server does not need to send 4-th share to client*/
#define LAST_SHARE_SERVER (-909)
/* the number of shares needed by client to restore files */
#define NUM_OF_SHARES_NEEDED 3

using namespace std;

/*shareMDBuffer format: [fileShareMDHead_t + full file name + shareMDEntry_t ... shareMDEntry_t] ...*/
/*the full file name includes the prefix path*/

/*the head structure of the file share metadata*/
typedef struct {
    int fullNameSize;
    long fileSize;
    int numOfPastSecrets;
    long sizeOfPastSecrets;
    int numOfComingSecrets;
    long sizeOfComingSecrets;
} fileShareMDHead_t;

/*dir inode value format: [inodeIndexValueHead_t + short name + inodeDirEntry_t ... inodeDirEntry_t]*/
/*file inode value format: [inodeIndexValueHead_t + short name + inodeFileEntry_t ... inodeFileEntry_t]*/
/*the short name excludes the prefix path*/

/*the head structure of the value of the inode index*/
typedef struct {
    int userID;
    int shortNameSize;
    bool inodeType;
    int numOfChildren;
} inodeIndexValueHead_t;

/*the dir entry structure of the value of the inode index*/
typedef struct {
    char inodeFP[FP_SIZE];
} inodeDirEntry_t;

/*the file entry structure of the value of the inode index*/
typedef struct {
    char recipeFileName[INTERNAL_FILE_NAME_SIZE];
    int recipeFileOffset;
} inodeFileEntry_t;

/*share index value format: [shareIndexValueHead_t + shareUserRefEntry_t ... shareUserRefEntry_t]*/

/*the head structure of the value of the share index*/
typedef struct {
    char shareContainerName[INTERNAL_FILE_NAME_SIZE];
    int shareContainerOffset;
    int shareSize;
    int numOfUsers;
} shareIndexValueHead_t;

/*the user reference entry structure of the value of the share index*/
typedef struct {
    int userID;
    int refCnt;
} shareUserRefEntry_t;

/*file recipe format: [fileRecipeHead_t + fileRecipeEntry_t ... fileRecipeEntry_t]*/

/*the head structure of the recipes of a file*/
typedef struct {
    int userID;
    long fileSize;
    int numOfShares;
} fileRecipeHead_t;

/*the entry structure of the recipes of a file*/
typedef struct {
    char shareFP[FP_SIZE];
    int secretID;
    int secretSize;
    int segID;
    int shareID;
} fileRecipeEntry_t;

/*the per-user buffer node structure*/
typedef struct perUserBufferNode {
    int userID;
    char recipeFileName[INTERNAL_FILE_NAME_SIZE];
    unsigned char recipeFileBuffer[RECIPE_BUFFER_SIZE];
    int recipeFileBufferCurrLen;
    int lastRecipeHeadPos;
    char lastInodeFP[FP_SIZE];
    char shareContainerName[INTERNAL_FILE_NAME_SIZE];
    unsigned char shareContainerBuffer[CONTAINER_BUFFER_SIZE];
    int shareContainerBufferCurrLen;
    double lastUseTime;
    struct perUserBufferNode *next;
} perUserBufferNode_t;

/*restored share file format: [shareFileHead_t + shareEntry_t + share data + ... + shareEntry_t + share data]*/

/*the head structure of the restored share file*/
typedef struct {
    long fileSize;
    int numOfShares;
} shareFileHead_t;

/*the entry structure of the restored share file*/
typedef struct {
    int secretID;
    int secretSize;
    int shareSize;
    int segID;
    int shareID;
} shareEntry_t;

/*the entry structure of the file share metadata*/
typedef struct {
    char shareFP[FP_SIZE];
    int secretID;
    int secretSize;
    int shareSize;
    int segID;
    int shareID;
} shareMDEntry_t;

/*the share container cache node structure*/
typedef struct {
    char shareContainerName[INTERNAL_FILE_NAME_SIZE];
    unsigned char shareContainer[CONTAINER_BUFFER_SIZE];
} shareContainerCacheNode_t;


/* file header object structure for ringbuffer */
typedef struct {
    shareFileHead_t file_header;
    char data[RING_BUFFER_DATA_SIZE];
} fileHeaderObj_t;

/* share header object structure for ringbuffer */
typedef struct {
    shareEntry_t share_header;
    unsigned char data[RING_BUFFER_DATA_SIZE];
} shareHeaderObj_t;

typedef struct {
    shareMDEntry_t share_header;
    char data[RING_BUFFER_META_SIZE];
} metaShareHeaderObj_t;

/* union of objects for unifying ringbuffer objects */
typedef struct {
    int type;
    union {
        fileHeaderObj_t fileObj;
        shareHeaderObj_t shareObj;
    };
} Item_t;

typedef struct {
    int type;
    union {
        fileHeaderObj_t fileObj;
        metaShareHeaderObj_t shareObj;
    };
} ItemMeta_t;

typedef struct {
    unsigned char shareFP[HASH_SIZE];
    int secretID;
    int secretSize;
    int shareSize;
    int segID;
    int shareID;
} metaNode;

typedef struct {
    int id;
    int shareID;
    int end_secretID;
} MetaList;
#endif
