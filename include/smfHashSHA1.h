#ifndef _SMF_HASH_SHA1
#define _SMF_HASH_SHA1
 
#include "smfHash.h"

class SmfHashSHA1 : public SmfHash
{
    public:
        SmfHashSHA1();
        ~SmfHashSHA1();
        
        void Init();
        void Update(const char* buffer, unsigned int buflen);
        void Finalize();
        
        Type GetType() const
            {return SHA1;}

        unsigned int GetLength() const
            {return 20;}        
        
        const char* GetValue() const
            {return ((char*)digest_buffer);} 
            
    private:
        void Transform();    
        
        UINT32  bit_count[2];
        UINT32  data_buffer[16];
        UINT32  digest_buffer[5];
               
};  // end class SmfHashSHA1

#endif // _SMF_HASH_SHA1
