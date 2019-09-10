 #ifndef _PATH
#define _PATH

 #include "protoAddress.h"

 class Path //linked list
{
    public:
        Path(const ProtoAddress& addr);
        Path(const ProtoAddress& addr, Path * p);
        void printPath();
        const ProtoAddress getAddress(){return addr;}
        Path * getNextPath(){return nextPath;}

    private:
        ProtoAddress addr;
        Path * nextPath;

};

#endif
