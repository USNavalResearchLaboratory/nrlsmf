/*********************************************************************
 *
 * AUTHORIZATION TO USE AND DISTRIBUTE
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: 
 *
 * (1) source code distributions retain this paragraph in its entirety, 
 *  
 * (2) distributions including binary code include this paragraph in
 *     its entirety in the documentation or other materials provided 
 *     with the distribution, and 
 *
 * (3) all advertising materials mentioning features or use of this 
 *     software display the following acknowledgment:
 * 
 *  The name of NRL, the name(s) of NRL  employee(s), or any entity
 *  of the United States Government may not be used to endorse or
 *  promote  products derived from this software, nor does the 
 *  inclusion of the NRL written and developed software  directly or
 *  indirectly suggest NRL or United States  Government endorsement
 *  of this product.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * Revision history
 * Date  Author Details
 * 01/07/05 William Chao init version 
 * 01/07/05 Justin Dean init version
 * 03/14/05 Brian Adamson version
 */
 
#ifndef _SMF_DUP_TREE
#define _SMF_DUP_TREE

#include "protoTree.h"
#include "protoAddress.h"
#include "smfWindow.h"

// (TBD) We need to time out stale entries in our tree!!!
//       (or else we have a potential tree growth problem)

class SmfDuplicateTree 
{
    public:
		SmfDuplicateTree ();
		~SmfDuplicateTree ();
        
		bool Init(UINT32    windowSize,     // in packets
                  UINT32    windowPastMax); // in packets
        void Destroy();
        
		bool IsDuplicate(unsigned int   currentTime,
                         UINT32         seqNum,
                         unsigned int   seqNumSize,      // in bits
                         const char*    seqContext,
                         unsigned int   seqContextSize); // in bits
        
        unsigned int GetCount() const
            {return flow_list.GetCount();}
        
        void Prune(unsigned int currentTime,
                   unsigned int ageMax);
    private:       
        class Flow : public ProtoTree::Item
        {
            public:
                Flow();
                ~Flow();
                
                bool Init(const char*         flowId,
                          unsigned int        flowIdSize,     // in bits
                          UINT8               seqNumSize,     // in bits
                          UINT32              windowSize,     // in packets
                          UINT32              windowPastMax); // in packets
                
                const char* GetKey() const {return flow_id;}
                
                unsigned int GetKeysize() const {return flow_id_size;}
                
                bool IsDuplicate(UINT32 seqNum)
                    {return window.IsDuplicate(seqNum);}
                
                void SetUpdateTime(unsigned int currentTime)
                    {update_time = currentTime;}
                
                unsigned int GetAge(unsigned int currentTime) const
                    {return (currentTime - update_time);}
                
                // List linking (used for aging/pruning entries)
                void Append(Flow* nextFlow)
                    {next = nextFlow;}
                void Prepend(Flow* prevFlow)
                    {prev = prevFlow;}
                Flow* GetPrev() {return prev;}
                Flow* GetNext() {return next;}
                
            private:
                char*               flow_id;
                unsigned int        flow_id_size;
                SmfSlidingWindow    window; 
                unsigned int        update_time;
                
                Flow*               prev;
                Flow*               next;
        };  // end class SmfDuplicateTree::Flow
        
        class FlowList
        {
            public:
                FlowList();
                ~FlowList();
                unsigned int GetCount() const
                    {return count;}
                void Prepend(Flow& flow)
                {
                    if (head)
                        head->Prepend(&flow);
                    else
                        tail = &flow;
                    flow.Prepend(NULL);
                    flow.Append(head);
                    head = &flow;
                    count++;
                }
                void Remove(Flow& flow)
                {
                    Flow* prev = flow.GetPrev();
                    Flow* next = flow.GetNext();
                    if (NULL != next)
                        next->Prepend(prev);
                    else
                        tail = prev;
                    if (NULL != prev)
                        prev->Append(next);
                    else
                        head = next;
                    count--;  
                }
                
                Flow* GetHead() const
                    {return head;}
                Flow* GetTail() const 
                    {return tail;}
            
            private:
                unsigned int count;
                Flow*        head;
                Flow*        tail;
        };  // end class SmfDuplicateTree::FlowList  
            
		ProtoTree   flow_tree;
        FlowList    flow_list;    // sorted linked list with most "current" at head
        UINT32      window_size;
		UINT32      window_past_max; 
                
};  // end class SmfDuplicateTree

// This class keeps per-flow (dst[:src] addr) sequence number
// state and is used for SMF source host resequencing purposes
class SmfSequenceMgr
{
    public:
        SmfSequenceMgr();
        ~SmfSequenceMgr();
        bool Init(UINT8 numSeqBits);
        void Destroy();
        
        UINT32 IncrementSequence(unsigned int        updateTime,
                                 const ProtoAddress* dstAddr, 
                                 const ProtoAddress* srcAddr = NULL);
        
        void Prune(unsigned int currentTime,
                   unsigned int ageMax);
        
    private: 
        class Flow : public ProtoTree::Item
        {
            public:
                Flow();
                ~Flow();
                
                bool Init(const char*  theKey,
                          unsigned int theKeylen);
                
                const char* GetKey() const {return flow_id;}
                unsigned int GetKeysize() const {return flow_id_size;}
                
                void SetSequence(UINT32 value)
                    {sequence = value;}
                UINT32 GetSequence() const
                    {return sequence;}
                UINT32 IncrementSequence(UINT32 seqMask)
                    {return (sequence++ & seqMask);}
                
                void SetUpdateTime(unsigned int updateTime)
                    {update_time = updateTime;}
                unsigned int GetAge(unsigned int currentTime) const
                    {return (currentTime - update_time);}
                
                void Append(Flow* flow)
                    {next = flow;}
                void Prepend(Flow* flow)
                    {prev = flow;}
                Flow* GetPrev() const
                    {return prev;}
                Flow* GetNext() const
                    {return next;}
                
            private:
                char*         flow_id;
                unsigned int  flow_id_size;
                UINT32        sequence;
                unsigned int  update_time;
                Flow*         prev;
                Flow*         next;
                
        };  // end class SmfSequenceMgr::Flow
        
        class FlowList
        {
            public:
                FlowList();
                ~FlowList();
                
                unsigned int GetCount() const
                    {return count;}
                void Prepend(Flow& flow)
                {
                    if (head)
                        head->Prepend(&flow);
                    else
                        tail = &flow;
                    flow.Prepend(NULL);
                    flow.Append(head);
                    head = &flow;
                    count++;
                }
                void Remove(Flow& flow)
                {
                    Flow* prev = flow.GetPrev();
                    Flow* next = flow.GetNext();
                    if (NULL != next)
                        next->Prepend(prev);
                    else
                        tail = prev;
                    if (NULL != prev)
                        prev->Append(next);
                    else
                        head = next;
                    count--;  
                }
                Flow* GetHead() const
                    {return head;}
                Flow* GetTail() const 
                    {return tail;}
            
            private:
                unsigned int    count;
                Flow*           head;
                Flow*           tail;
        };  // end class SmfSequenceMgr::FlowList  
        
        UINT32              seq_mask;
        UINT32              seq_global;
        ProtoTree           flow_tree;  
        FlowList            flow_list;
               
};  // end class SmfSequenceMgr

#endif // !_SMF_DUP_TREE
