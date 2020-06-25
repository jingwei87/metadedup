#ifndef __DATASTRUCT_HH__
#define __DATASTRUCT_HH__

#define HASH_SIZE 32
#define KEY_SIZE 32
#define FP_SIZE 32
#define KEYEX_COMPUTE_SIZE 128

/* num of total servers. 5 is default(= TOTAL_SHARES_NUM + 1) */
#define TOTAL_SERVERS_NUM 5
/* num of total shares in current version of system. 4 is default(= k + 1) */
#define TOTAL_SHARES_NUM 4

/* max chunk data size. Its value depends on setting of chunker. default: 4 * 16KB */
#define MAX_DATA_SIZE (TOTAL_SHARES_NUM * 16 * 1024)

/* max secret size */
#define SECRET_SIZE (16 * 1024)
// META_BUFFER supports up to 16MB segment size
#define SECRET_SIZE_META (1250 * 1024)

/* max share buffer size */
#define SHARE_BUFFER_SIZE (4 * 16 * 1024)

/* data buffer size for each object in ringbuffer */
// META_BUFFER supports up to 16MB segment size
#define RING_BUFFER_DATA_SIZE (16 * 1024)
#define RING_BUFFER_META_SIZE (1250 * 1024)

/* file head structure */
typedef struct {
    unsigned char file_name[SECRET_SIZE];
    int fullNameSize;
    long fileSize;
} fileHead_t;

/* file metadata header structure */
typedef struct {
    int fullNameSize;
    long fileSize;
    int numOfPastSecrets;
    long sizeOfPastSecrets;
    int numOfComingSecrets;
    long sizeOfComingSecrets;
} fileShareMDHead_t;

/* file header object struct for ringbuffer */
typedef struct {
    fileHead_t file_header;
    fileShareMDHead_t file_shareMD_header;
    unsigned char encoded_file_name[RING_BUFFER_DATA_SIZE];
} FileHeader_t;

/* the chunk structure for storing all data.
 * Member is listed below:
 *    content[SIZE] // store chunk data content
 *    total_FP[SHARE_NUM * FP_SIZE] // store chunk FP and all shareFP
 *    chunk_id // store the ID of data chunk (secretID)
 *    seg_id // store the ID of segment
 *    share_id // store the ID of current share
 *    chunk_size // store the size of chunk data
 *    share_size // store the size of share size
 *    kmCloudIndex // store the server index of Key-Exchanged Server
 *    end // indicate for ending: 0 means share_object(not ending), 1 means ending
 * */
typedef struct {
    unsigned char content[MAX_DATA_SIZE];
    unsigned char total_FP[TOTAL_SHARES_NUM * FP_SIZE];
    int chunk_id;
    int seg_id;
    int share_id;
    short chunk_size;
    short share_size;
    short kmCloudIndex;
    short end;
} Chunk_t;

#endif // __DATASTRUCT_HH__
