/*
 * DedupCore.hh
 *
 * Handle meta data port
 */

#ifndef __DEDUCORE_HH__
#define __DEDUCORE_HH__

#include <arpa/inet.h>
#include <errno.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/*for the use of LevelDB*/
#include "leveldb/db.h"
/*for the use of Slice*/
#include "leveldb/slice.h"
/*for the use of write batch*/
#include "leveldb/write_batch.h"
/*for the use of cache*/
#include "leveldb/cache.h"
/*for the use of Bloom filter*/
#include "leveldb/filter_policy.h"

/*for the use of BackendStorer*/
#include "BackendStorer.hh"

/*for the use of CryptoPrimitive*/
#include "CryptoPrimitive.hh"

#include "dataStruct.hh"
#include "Logger.hh"

class DedupCore {
private:
    /*the name of the deduplication directory*/
    std::string dedupDirName_;

    /*variables for the key-value DB*/
    std::string dbDirName_;
    leveldb::DB *db_;
    leveldb::Options dbOptions_;
    leveldb::ReadOptions readOptions_;
    leveldb::WriteOptions writeOptions_;
    leveldb::WriteBatch batch_;

    /*variables for cloud storage backend*/
    BackendStorer *recipeStorerObj_;
    BackendStorer *containerStorerObj_;

    /*variables for the file share metadata*/
    int fileShareMDHeadSize_;
    int shareMDEntrySize_;

    /*variables for the inode key-value index*/
    int inodeIndexValueHeadSize_;
    int inodeDirEntrySize_;
    int inodeFileEntrySize_;

    /*variables for the share key-value index*/
    int shareIndexValueHeadSize_;
    int shareUserRefEntrySize_;

    /*variables for file recipes*/
    std::string recipeFileDirName_;
    std::string globalRecipeFileName_;
    int recipeFileNameValidLen_;
    int fileRecipeHeadSize_;
    int fileRecipeEntrySize_;

    /*variables for share containers*/
    std::string shareContainerDirName_;
    std::string globalShareContainerName_;
    int shareContainerNameValidLen_;

    /*variables for buffer nodes*/
    perUserBufferNode_t *headBufferNode_;
    perUserBufferNode_t *tailBufferNode_;
    int perUserBufferNodeSize_;

    /*variables for restored share file*/
    int shareFileHeadSize_;
    int shareEntrySize_;

    /*a mutex lock for the database*/
    pthread_mutex_t DBLock_;

    /*a mutex lock for the buffer node link*/
    pthread_mutex_t bufferLock_;

    /*a mutex lock for the global recipe file name*/
    pthread_mutex_t globalRecipeFileNameLock_;

    /*a mutex lock for the global share container name*/
    pthread_mutex_t globalShareContainerNameLock_;

    /*indicate for a last_share on this server, this server is special for client*/
    bool last_share_on_server_;

    /*
     * format a full file name (including the path) into '/.../.../shortName'
     *
     * @param fullFileName - the full file name to be formated <return>
     *
     * @return - a boolean value that indicates if the formating succeeds
     */
    bool formatFullFileName_(std::string &fullFileName);

    /*
     * format a directory name into '.../.../shortName/'
     *
     * @param dirName - the directory name to be formated <return>
     *
     * @return - a boolean value that indicates if the formating succeeds
     */
    bool formatDirName_(std::string &dirName);

    /*
     * prefix a (directory or file) name with a directory name
     *
     * @param prefixDirName - the prefix directory name to be formated
     * @param name - the (directory or file) name to be prefixed <return>
     *
     * @return - a boolean value that indicates if the prefixing succeeds
     */
    bool addPrefixDir_(const std::string &prefixDirName, std::string &name);

    /*
     * check if a file (or directory) is accessible
     *
     * @param name - the name of the file to be checked
     *
     * @return - a boolean value that indicates if the file is accessible
     */
    inline bool checkFileAccess_(const std::string &name);

    /*
     * check if a file (or directory) exists
     *
     * @param name - the name of the file to be checked
     *
     * @return - a boolean value that indicates if the file exists
     */
    inline bool checkFileExistence_(const std::string &name);

    /*
     * check if a file (or directory) can be accessed with all permissions
     *
     * @param name - the name of the file to be checked
     *
     * @return - a boolean value that indicates if the file can be accessed with all permissions
     */
    inline bool checkFilePermissions_(const std::string &name);

    /*
     * get the size of an opened file
     *
     * @param fp - the file pointer
     *
     * @return - the size of the file
     */
    inline long getFileSize_(FILE *fp);

    /*
     * recursively create a directory
     *
     * @param dirName - the name (which ends with '/') of the directory to be created
     *
     * @return - a boolean value that indicates if the create op succeeds
     */
    bool createDir_(const std::string &dirName);

    /*
     * increment a global file name in lexicographical order
     *
     * @param fileName - the file name to be incremented <return>
     * @param validLen - the length of the file name excluding the suffix
     *
     * @return - a boolean value that indicates if the incrementing succeeds
     */
    bool incrGlobalFileName_(std::string &fileName, const int &validLen);

    /*
     * transform a file name to an inode's fingerprint
     *
     * @param fullFileName - the full file name to be transformed 
     * @param userID - the user id
     * @param inodeFP - the resulting inode's fingerprint <return>
     * @param cryptoObj - the CryptoPrimitive instance for calculating hash fingerprint
     *
     * @return - a boolean value that indicates if the transformation succeeds
     */
    inline bool fileName2InodeFP_(const std::string &fullFileName, const int &userID, char *inodeFP,
                                  CryptoPrimitive *cryptoObj);

    /*
     * transform an inode's fingerprint to an index key
     *
     * @param inodeFP - the inode's fingerprint to be transformed 
     * @param key - the resulting index key <return>
     */
    inline void inodeFP2IndexKey_(char *inodeFP, char *key);

    /*
     * transform a share's fingerprint to an index key
     *
     * @param shareFP - the share's fingerprint to be transformed 
     * @param key - the resulting index key <return>
     */
    inline void shareFP2IndexKey_(char *shareFP, char *key);

    /*
     * get the current time (in second)
     *
     * @param time - the current time <return>
     */
    inline void getCurrTime_(double &time);

    /*
     * flush a buffer node into the disk
     *
     * @param targetBufferNode - the buffer node to be flushed 
     *
     * @return - a boolean value that indicates if the flush op succeeds
     */
    bool flushBufferNodeIntoDisk_(perUserBufferNode_t *targetBufferNode);

    /*
     * find or create a buffer node for a user in the buffer node link
     *
     * @param userID - the user id
     * @param targetBufferNode - the resulting buffer node <return>
     */
    void findOrCreateBufferNode_(const int &userID, perUserBufferNode_t *&targetBufferNode);

    /*
     * add a file's information into the inode index
     *
     * @param fullFileName - the full name of the file to be added 
     * @param userID - the user id 
     * @param targetBufferNode - the corresponding buffer node 
     * @param cryptoObj - the CryptoPrimitive instance for calculating hash fingerprint
     *
     * @return - a boolean value that indicates if the add op succeeds
     */
    bool addFileIntoInodeIndex_(const std::string &fullFileName, const int &userID,
                                perUserBufferNode_t *targetBufferNode, CryptoPrimitive *cryptoObj);

    /*
     * update the index for a share based on intra-user deduplication
     *
     * @param shareFP - the fingerprint of the share 
     * @param userID - the user id 
     * @param intraUserDupStat - a boolean value that indicates if the key is a duplicate <return>
     *
     * @return - a boolean value that indicates if the update op succeeds
     */
    bool intraUserIndexUpdate_(char *shareFP, const int &userID, bool &intraUserDupStat);

    /*
     * update the index for a share based on inter-user deduplication
     *
     * @param shareFP - the fingerprint of the share 
     * @param userID - the user id 
     * @param shareSize - the size of the corresponding share 
     * @param targetBufferNode - the corresponding buffer node 
     * @param shareDataBuffer - the share data buffer
     * @param shareDataBufferOffset - the offset of the share data buffer
     *
     * @return - a boolean value that indicates if the update op succeeds
     */
    bool interUserIndexUpdate_(char *shareFP, const int &userID, const int &shareSize,
                               perUserBufferNode_t *targetBufferNode, unsigned char *shareDataBuffer,
                               const int &shareDataBufferOffset);

    /*
     * store the data of the recipe file buffer into a new recipe file
     *
     * @param targetBufferNode - the corresponding buffer node 
     * @param recipeFileName - the recipe file name <return>
     *
     * @return - a boolean value that indicates if the store op succeeds
     */
    bool storeNewRecipeFile_(perUserBufferNode_t *targetBufferNode, std::string &recipeFileName);

    /*
     * find an old recipe file for appending the data of the recipe file buffer
     *
     * @param targetBufferNode - the corresponding buffer node 
     * @param recipeFileName - the name of the found old recipe file <return>
     * @param recipeFileOffset - the offset of the found old recipe file <return>
     *
     * @return - a boolean value that indicates if the find op succeeds
     */
    bool findOldRecipeFile_(perUserBufferNode_t *targetBufferNode, std::string &recipeFileName, int &recipeFileOffset);

    /*
     * append the data of the recipe file buffer to an old recipe file
     *
     * @param targetBufferNode - the corresponding buffer node 
     * @param recipeFileName - the recipe file name <return> 
     *
     * @return - a boolean value that indicates if the append op succeeds
     */
    bool appendOldRecipeFile_(perUserBufferNode_t *targetBufferNode, std::string &recipeFileName);

    /*
     * store the data of the share container buffer into a container
     *
     * @param targetBufferNode - the corresponding buffer node 
     * @param shareContainerName - the share container name <return> 
     *
     * @return - a boolean value that indicates if the store op succeeds
     */
    bool storeShareContainer_(perUserBufferNode_t *targetBufferNode, std::string &shareContainerName);

    /*
     * read the recipe file from the buffer node link
     *
     * @param userID - the user id
     * @param recipeFileName - the name of the recipe file
     * @param recipeFileBuffer - the buffer for storing the recipe file <return>
     *
     * @return - a boolean value that indicates if the read op succeeds
     */
    bool readRecipeFileFromBuffer_(const int &userID, char *recipeFileName,
                                   unsigned char *recipeFileBuffer);

    /*
     * read the share container from the buffer node link
     *
     * @param shareContainerName - the name of the share container
     * @param shareContainerBuffer - the buffer for storing the share container <return>
     *
     * @return - a boolean value that indicates if the read op succeeds
     */
    bool readShareContainerFromBuffer_(char *shareContainerName,
                                       unsigned char *shareContainerBuffer);

    /*
     * write a new metaNode into file (write data file recipes)
     *
     * @param fp - the pointer to opened file
     * @param metaNode - meta node to be added to file
     * @param fileSizeCounter - count the file size <return>
     * @param index - debugging only
     *
     * @return - a boolean value that indicates if the write succeeds
     */
    bool saveMetaNode2DataFileRecipe(FILE *fp, metaNode *node, int &fileSizeCounter, int index);

    /*
     * send file recipe indicator to client
     *
     * @param socketFD - the file descriptor of the sending socket
     *
     * @return - a boolean value that indicates if the operation succeeds
     */
    bool sendFileRecipeIndicator(int socketFD);

public:
    /*
     * constructor of DedupCore
     *
     * @param dedupDirName - the name of the directory that stores all deduplication-related data
     * @param dbDirName - the name of the directory that stores the key-value database
     * @param recipeFileDirName - the name of the directory that stores the recipe files
     * @param shareContainerDirName - the name of the directory that stores the share containers
     * @param recipeStorerObj - the BackendStorer instance that manages recipe files
     * @param containerStorerObj - the BackendStorer instance that manages share containers	
     */
    DedupCore(const std::string &dedupDirName = "./",
              const std::string &dbDirName = "DedupDB/",
              const std::string &recipeFileDirName = "RecipeFiles/",
              const std::string &shareContainerDirName = "ShareContainers/",
              BackendStorer *recipeStorerObj = NULL,
              BackendStorer *containerStorerObj = NULL);

    /*
     * destructor of DedupCore 
     */
    ~DedupCore();

    /*
     * perform the first-stage deduplication
     *
     * @param userID - the user id 
     * @param shareMDBuffer - the buffer that stores the share metadata
     * @param shareMDSize - the size of the share metadata buffer
     * @param intraUserDupStatList - a list that records the intra-user duplicate status of each share <return>
     * @param numOfShares - the total number of processed shares <return>
     * @param sentShareDataSize - the total size of share data that should be sent by the client <return>
     *
     * @return - a boolean value that indicates if the first-stage deduplication succeeds
     */
    bool firstStageDedup(const int &userID, unsigned char *shareMDBuffer, const int &shareMDSize,
                         bool *intraUserDupStatList, int &numOfShares, int &sentShareDataSize);

    /*
     * perform the second-stage deduplication
     *
     * @param userID - the user id 
     * @param shareMDBuffer - the buffer that stores the share metadata
     * @param shareMDSize - the size of the share metadata buffer
     * @param intraUserDupStatList - a list that records the intra-user duplicate status of each share 
     * @param shareDataBuffer - the share data buffer
     * @param cryptoObj - the CryptoPrimitive instance for calculating hash fingerprint
     * @param end - indicate ending for metaDedupCore
     *
     * @return - a boolean value that indicates if the second-stage deduplication succeeds
     */
    bool secondStageDedup(const int &userID, unsigned char *shareMDBuffer, const int &shareMDSize,
                          bool *intraUserDupStatList,
                          unsigned char *shareDataBuffer, CryptoPrimitive *cryptoObj, bool end);

    /*
     * clean up the buffer node for a user in the buffer node link
     *
     * @param userID - the user id
     *
     * @return - a boolean value that indicates if the clean-up op succeeds
     */
    bool cleanupUserBufferNode(const int &userID);

    /*
     * clean up the buffer nodes for all users in the buffer node link
     *
     * @return - a boolean value that indicates if the clean-up op succeeds
     */
    bool cleanupAllBufferNodes();

    /*
     * restore a share file for a user and write file recipe
     *
     * @param userID - the user id
     * @param fullFileName - the full name of the original file
     * @param versionNumber - the version number (<=0) of the original file
     * @param socketFD - the file descriptor of the sending socket
     * @param cryptoObj - the CryptoPrimitive instance for calculating hash fingerprint
     *
     * @return - a boolean value that indicates if the restore op succeeds
     */
    bool restoreShareFileAndWriteFileRecipe(const int &userID,
                                            const std::string &fullFileName, const std::string &fileRecipeName,
                                            const int &versionNumber, int socketFD, CryptoPrimitive *cryptoObj);

    /*
     * extract ID and shareID from file recipes
     *
     * @param meta_list - the buffer for storing the shorted version of metadata file recipes
     * @param id - the ID of this metadata chunk
     * @param shareID - the shareID of data shares this metadata chunk contains
     * @param write_index - the index pointing to the location of writing
     * @param end_secretID - the end of secretID in this meta_list(necessary)
     *
     * @return - a boolean value that indicates if the op succeeds
     */
    bool save_as_metalist(unsigned char *meta_list_buffer, int id, int shareID, int write_index,
                          int end_secretID);

    /*
     * assemble complete-version of meta_list_buffer and prepare for sending
     *
     * @param meta_list_buffer - the buffer storing all metalist(information) in this server<return>
     * @param count - count how many MetaList in this buffer
     * @param total_size - total size of this buffer<return>
     */
    void assemble_full_meta_list_buffer(unsigned char *meta_list_buffer, int &count);

    /*
     * send buffer back to client
     *
     * @param buffer - buffer to be sent
     * @param total_size - total size of this buffer
     * @param count - count how many MetaList in this buffer
     * @param socketFD - the file descriptor of the sending socket
     */
    bool send_meta_list(unsigned char *metalist_buffer, int total_size, int count, int socketFD);

    /*
     * set special flag for this server
     *
     * @param flag - for indicating this is special server which has the 4-th share
     *               and it is no need to send back to client
     */
    void set_last_share_special_flag(bool flag);

    /*
     * get special flag for this server
     *
     * @param flag - for indicating this is special server which has the 4-th share
     *               and it is no need to send back to client
     */
    bool get_last_share_special_flag();
};

#endif
