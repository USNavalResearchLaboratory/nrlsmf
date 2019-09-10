#ifndef _SMF_HASH_MD5
#define _SMF_HASH_MD5

#include "smfHash.h"

class SmfHashMD5 : public SmfHash
{
    public:
        SmfHashMD5();
        ~SmfHashMD5();
        
        void Init();
        void Update(const char* buffer, unsigned int buflen);
        void Finalize();
        
        Type GetType() const
            {return MD5;}
        
        unsigned int GetLength() const
            {return 16;}
        
        const char* GetValue() const
            {return ((char*)digest_buffer);} 
            
    private:
        void Transform();       
        static inline void ByteReverse(UINT32* buffer, unsigned int count);     
        
        UINT32  bit_count[2];
        UINT32  digest_buffer[4];
        UINT32  data_buffer[16];   
               
};  // end class SmfHashMD5


#endif // _SM_HASH_MD5

