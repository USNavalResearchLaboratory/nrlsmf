#ifndef _SMF_HASH
#define _SMF_HASH

#include <protoPktIP.h>

class SmfHash
{
    public:
        enum Type 
        {
            NONE = 0,   // no hashing used (also invalid)
            MD5,        // MD5 hash of packet
            CRC32,      // CRC-32 checksum
            SHA1,       // SHA-1 hash
            INVALID
        };
           
        virtual ~SmfHash();
        
        
        // Required overrides
        virtual Type GetType() const = 0; 
        virtual unsigned int GetLength() const = 0;  // in bytes
        virtual const char* GetValue() const = 0;
        
        virtual void Init() = 0;
        virtual void Update(const char* buffer, unsigned int buflen) = 0;
        virtual void Finalize() = 0;
        
        // Some helper methods
        void Compute(const char* buffer, unsigned int buflen);
        void ComputeHashIPv4(ProtoPktIPv4& ip4Pkt);     
        void ComputeHashIPv6(ProtoPktIPv6& ip6Pkt);
            
        static const char* GetName(Type hashType)
            {return TYPE_NAMES[(int)hashType];}
        
        static Type GetTypeByName(const char* name);
        
        
        // Compute or update an existing checksum
        static UINT32 ComputeCRC32(const char*  buffer, 
                                   unsigned int buflen,
                                   UINT32*      checksum = NULL);
            
    protected:
        SmfHash();         
        
    private:
        static const char* const TYPE_NAMES[];
        
};  // end class SmfHash



class SmfHashCRC32 : public SmfHash
{
    public: 
        SmfHashCRC32();
        ~SmfHashCRC32();
        
        Type GetType() const 
            {return CRC32;}
        unsigned int GetLength() const
            {return 4;}
        const char* GetValue() const
            {return ((const char*)&checksum);}
        
        void Init()
            {checksum = CRC32_XINIT;}
        void Update(const char* buffer, unsigned int buflen);
        void Finalize()
            {checksum ^= CRC32_XOROT;}
        
    private:
        static const UINT32 CRC32_XINIT;
        static const UINT32 CRC32_XOROT;
        static const UINT32 CRC32_TABLE[256];
        
        UINT32  checksum;
};  // end class SmfHashCRC32


#endif // _SMF_HASH
