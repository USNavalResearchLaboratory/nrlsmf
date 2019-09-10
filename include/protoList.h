// This is a sorted linked list with a fixed cost to find items in
// the list by their "key".  The ProtoList can be iterated (in order 
// or in reverse order) as efficiently as a linked list.  This is 
// implemented by dually storing items (indexed by "key") in a
// prefix-based Patricia Trie (ProtoTree) as well as a linked list.
// Entries with the same "key" value may be stored.  Note that adding
// to the list _and_ removal of the list are also have fixed cost.
// (The cost is limited by the key length).


#ifndef _PROTO_LIST
#define _PROTO_LIST

#include "protoTree.h"

class ProtoList
{
    public:
        ProtoList(const char*    theKey = NULL, 
                  unsigned int   theKeysize = 0, 
                  void*          theValue = NULL);  
        ~ProtoList();
        
        bool Init(unsigned int theKeysize);  // in "bits"
        
        class Item : public ProtoTree::Item
        {
            public:
                Item();
                ~Item();
                
                Item* GetNext() {return next;}
                Item* GetPrev() {return prev;}
                
            private:
                Item*   prev;
                Item*   next;
                
        };  // end class ProtoList::Item()
            
    private:
        ProtoTree   ptree;
        Item*       head;
        Item*       tail;
        
};  // end class ProtoList

#endif // _PROTO_LIST
