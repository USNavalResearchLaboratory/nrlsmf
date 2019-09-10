#ifndef _PROTO_GRAPH
#define _PROTO_GRAPH

#include <protoTree.h>
#include <protoDebug.h>

class ProtoGraph
{
    public:
        class Vertice;

        class Edge
        {
            friend class Vertice;
            
            public:
                Edge(Vertice& a, Vertice& b);
                virtual ~Edge();

                Vertice& GetDst(const Vertice& src) const
                    {return ((&src == &term_a) ? term_b : term_a);}
                
            protected:    
                Edge* GetNext(const Vertice& vertice) const
                {
                    ASSERT((&vertice == &term_a) || (&vertice == &term_b));
                    return ((&vertice == &term_a) ? next_a : next_b);
                }
                
                void AppendToVertices();
                void DetachFromVertices();
                
                void Prepend(const Vertice& vertice, Edge* edge)
                {
                    ASSERT((&vertice == &term_a) || (&vertice == &term_b));
                    if (&vertice == &term_a)
                        prev_a = edge;
                    else
                        prev_b = edge;
                }
                void Append(const Vertice& vertice, Edge* edge)
                {
                    ASSERT((&vertice == &term_a) || (&vertice == &term_b));
                    if (&vertice == &term_a)
                        next_a = edge;
                    else
                        next_b = edge;
                }

                Vertice&    term_a;
                Edge*       prev_a;
                Edge*       next_a;

                Vertice&    term_b;
                Edge*       prev_b;
                Edge*       next_b;

        };  // end class Edge

        class Vertice
        {
            friend class Edge;
            
            public:
                ~Vertice();    

                // Required overrides (need these to enable inserting 
                //                     vertices into ProtoGraph tree)
                virtual const char* GetKey() const = 0;
                virtual unsigned int GetKeyLength() const = 0;
                
                // Core methods
                void SetVisited(bool status) {visited = status;}
                bool WasVisited() const {return visited;}

                class EdgeIterator;
                friend class EdgeIterator;
                class EdgeIterator
                {
                    public:
                        EdgeIterator(Vertice& theVertice);
                        ~EdgeIterator();

                        void Reset()
                            {next_edge = vertice.GetHeadEdge();}

                        Edge* GetNextEdge()
                        {
                            Edge* edge = next_edge;
                            next_edge = vertice.GetNextEdge(edge);
                            return edge;   
                        }

                    private:
                         Vertice&   vertice;
                         Edge*      next_edge;   

                };  // end class Vertice::EdgeIterator

                // Simple queue class to use for _temporary_ traversal purposes
                // (uses Vertice "queue_prev" & "queue_next" members)
                class Queue
                {
                    public:
                        Queue();
                        ~Queue();

                        void Empty() {head = tail = NULL;}
                        void Prepend(Vertice& vertice);
                        void Append(Vertice& vertice);
                        void Remove(Vertice& vertice);
                        Vertice* RemoveHead()
                        {
                            Vertice* vertice = head;
                            if (vertice) Remove(*vertice);
                            return vertice;   
                        };
                        void InsertBefore(Vertice& theVertice, Vertice& nextVertice);
                        void InsertAfter(Vertice& theVertice, Vertice& prevVertice);
                        
                        class Iterator
                        {
                            public:
                                Iterator(Vertice::Queue& theQueue, bool reverse = false);
                                ~Iterator();

                                void Reset();
                                Vertice* GetNextVertice();
                                
                            private:
                                Vertice::Queue& queue;
                                Vertice*        next_vertice;
                                bool            forward;

                        };  // end class Vertice::Queue::Iterator

                    protected:
                        Vertice* head;
                        Vertice* tail;
                };  // end class MrbInterface::Queue
                friend class Queue;
                friend class Queue::Iterator;

            protected:
                Vertice();
            
            private:
                Edge* GetNextEdge(Edge* edge) 
                    {return (edge ? edge->GetNext(*this) : NULL);}
                
                Edge* GetHeadEdge() {return edge_list_head;}
                void SetHeadEdge(Edge* edge) {edge_list_head = edge;}
                Edge* GetTailEdge() {return edge_list_tail;}
                void SetTailEdge(Edge* edge) {edge_list_tail = edge;}

                void QueuePrepend(Vertice* vertice) {queue_prev = vertice;}
                void QueueAppend(Vertice* vertice) {queue_next = vertice;}
                Vertice* GetQueuePrev() {return queue_prev;}
                Vertice* GetQueueNext() {return queue_next;}

                // List of edges (TBD - could this be singly-linked instead?)
                Edge*       edge_list_head;
                Edge*       edge_list_tail;
                
                // These members are for use by traversals and 
                // queue manipulations as needed
                // Marker to set/unset status (TBD - int instead of bool?)
                bool        visited;

                // Queue linker members
                Vertice*    queue_prev;
                Vertice*    queue_next;

        };  // end class Vertice

        ProtoGraph();
        ~ProtoGraph();

        bool InsertVertice(Vertice& vertice);
        void RemoveVertice(Vertice& vertice);
        
        Vertice* FindVertice(const char* key, unsigned int numBits)
        {
            ProtoTree::Item* item = ptree.Find(key, numBits);  
            return (NULL != item) ? (Vertice*)(item->GetValue()) : NULL; 
        }

        class VerticeIterator  : public ProtoTree::Iterator
        {
            public:
                VerticeIterator(ProtoGraph& nodeTree);
                ~VerticeIterator();

                void Reset() {ProtoTree::Iterator::Reset();}

                Vertice* GetNextVertice()
                {
                    ProtoTree::Item* item = GetNextItem();
                    return (item ? ((Vertice*)(item->GetValue())) : NULL);
                }
        };  // end class ProtoGraph::VerticeIterator

        // Breadth-first search traversal
        // (Note: treats edges as bi-directional connections)
        class Traversal
        {
            public:
                Traversal(ProtoGraph&   verticeTree, 
                          Vertice&      startVertice,
                          bool          depthFirst = false);
                ~Traversal();
                void Reset();
                virtual Vertice* GetNextVertice(unsigned int* level = NULL);

            protected:
                // Members
                ProtoGraph&     vertice_tree;
                Vertice&        start_vertice;
                bool            depth_first;    // false == bread first search
                unsigned int    current_level;
                Vertice*        trans_vertice;  // level transition

                Vertice::Queue  queue;
                
        };  // end class ProtoGraph::Traversal

    private:
        ProtoTree::Item* GetItemFromPool();
        void ReturnItemToPool(ProtoTree::Item& item);

        enum {POOL_DEPTH_MIN = 8};    

        ProtoTree               ptree;
        ProtoTree::Item::Pool   item_pool;  
        unsigned int            item_pool_depth;
        unsigned int            item_pool_count;  
            
};  // end class ProtoGraph





#endif // _PROTO_GRAPH
