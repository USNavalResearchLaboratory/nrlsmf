#include "protoGraph.h"

ProtoGraph::Edge::Edge(Vertice& a, Vertice& b)
 : term_a(a), prev_a(NULL), next_a(NULL),
   term_b(b), prev_b(NULL), next_b(NULL)
{
    AppendToVertices();
}

ProtoGraph::Edge::~Edge()
{
    DetachFromVertices();
}

void ProtoGraph::Edge::AppendToVertices()
{
    if ((prev_a = term_a.GetTailEdge()))
        prev_a->Append(term_a, this);
    else
        term_a.SetHeadEdge(this);
    term_a.SetTailEdge(this); 
    next_a = NULL;  
    
    if ((prev_b = term_b.GetTailEdge()))
        prev_b->Append(term_b, this);
    else
        term_b.SetHeadEdge(this);
    term_b.SetTailEdge(this); 
    next_b = NULL; 
}  // end ProtoGraph::Edge::AppendToVertice()

void ProtoGraph::Edge::DetachFromVertices()
{
   if (NULL != prev_a)
       prev_a->Append(term_a, next_a);
   else
       term_a.SetHeadEdge(next_a);
   if (NULL != next_a)
       next_a->Prepend(term_a, prev_a);
   else
       term_a.SetTailEdge(prev_a);
   prev_a = next_a = NULL; 
       
  if (NULL != prev_b)
      prev_b->Append(term_b, next_b);
   else
       term_b.SetHeadEdge(next_b);
   if (NULL != next_b)
       next_b->Prepend(term_b, prev_b);
   else
       term_b.SetTailEdge(prev_b); 
   prev_b = next_b = NULL; 
}  // end ProtoGraph::Edge::DetachVertice()
        
ProtoGraph::Vertice::Vertice()
 : edge_list_head(NULL), edge_list_tail(NULL), 
   queue_prev(NULL), queue_next(NULL)
{
}

ProtoGraph::Vertice::~Vertice()
{
    // Delete edges associated with this vertice
    Edge* next = edge_list_head;
    while (NULL != next)
    {
        Edge* edge = next;
        next = next->GetNext(*this);
        delete edge;      
    }
    edge_list_head = edge_list_tail = NULL;
} 

ProtoGraph::Vertice::EdgeIterator::EdgeIterator(Vertice& theVertice)
 : vertice(theVertice), next_edge(theVertice.GetHeadEdge())
{
}

ProtoGraph::Vertice::EdgeIterator::~EdgeIterator()
{
}

ProtoGraph::Vertice::Queue::Queue()
 : head(NULL), tail(NULL)
{
}

ProtoGraph::Vertice::Queue::~Queue()
{
}

void ProtoGraph::Vertice::Queue::Prepend(Vertice& vertice)
{
    vertice.QueuePrepend(NULL);
    if (NULL == head)
        tail = &vertice;
    else
        head->QueuePrepend(&vertice);
    vertice.QueueAppend(head);
    head = &vertice;
}  // end ProtoGraph::Vertice::Queue::Prepend()

void ProtoGraph::Vertice::Queue::Append(Vertice& vertice)
{
    vertice.QueueAppend(NULL);
    if (NULL == tail)
        head = &vertice;
    else
        tail->QueueAppend(&vertice);
    vertice.QueuePrepend(tail);
    tail = &vertice;
}  // end ProtoGraph::Vertice::Queue::Append()

void ProtoGraph::Vertice::Queue::Remove(Vertice& vertice)
{
    Vertice* prevVertice = vertice.GetQueuePrev();
    Vertice* nextVertice = vertice.GetQueueNext();
    if (prevVertice)
        prevVertice->QueueAppend(nextVertice);
    else
        head = nextVertice;
    if (nextVertice)
        nextVertice->QueuePrepend(prevVertice);
    else
        tail = prevVertice;
}  // end ProtoGraph::Vertice::Queue::Remove()

void ProtoGraph::Vertice::Queue::InsertBefore(Vertice& theVertice, 
                                              Vertice& nextVertice)
{
    Vertice* prevVertice = nextVertice.GetQueuePrev();
    if (NULL == prevVertice)
        head = &theVertice;
    else
        prevVertice->QueueAppend(&theVertice);
    theVertice.QueuePrepend(prevVertice);
    theVertice.QueueAppend(&nextVertice);
    nextVertice.QueuePrepend(&theVertice);   
}  // end ProtoGraph::Vertice::Queue::InsertBefore()

void ProtoGraph::Vertice::Queue::InsertAfter(Vertice& theVertice, 
                                             Vertice& prevVertice)
{
    Vertice* nextVertice = prevVertice.GetQueueNext();
    if (NULL == nextVertice)
        tail = &theVertice;
    else
        nextVertice->QueuePrepend(&theVertice);
    theVertice.QueuePrepend(&prevVertice);
    theVertice.QueueAppend(nextVertice);
    prevVertice.QueueAppend(&theVertice);   
}  // end ProtoGraph::Vertice::Queue::InsertAfter()

ProtoGraph::Vertice::Queue::Iterator::Iterator(Queue& theQueue, bool reverse)
 : queue(theQueue), next_vertice(reverse ? theQueue.tail : theQueue.head), forward(!reverse)
{
}

ProtoGraph::Vertice::Queue::Iterator::~Iterator()
{
}

void ProtoGraph::Vertice::Queue::Iterator::Reset()
{
    next_vertice = forward ? queue.head : queue.tail;
}  // end ProtoGraph::Vertice::Queue::Iterator::Reset()

ProtoGraph::Vertice* ProtoGraph::Vertice::Queue::Iterator::GetNextVertice()
{
    Vertice* vertice = next_vertice;
    next_vertice = vertice ? 
                        (forward ? vertice->GetQueueNext() : vertice->GetQueuePrev()) :
                        NULL;
    return vertice;
}  // end ProtoGraph::Vertice::Queue::Iterator::GetNextVertice()


ProtoGraph::ProtoGraph()
 : item_pool_depth(0), item_pool_count(0)
{
}

ProtoGraph::~ProtoGraph()
{
    // (TBD) destroy the tree, its nodes, their vertices and respective edges
    ProtoTree::Item* item;
    while (NULL != (item = ptree.GetRoot()))
    {
        Vertice* vertice = (Vertice*)(item->GetValue());
        ASSERT(NULL != vertice);
        RemoveVertice(*vertice);
        delete vertice;
    }
    item_pool.Destroy();
    item_pool_count = item_pool_depth = 0;
}

#include <protoAddress.h>

bool ProtoGraph::InsertVertice(Vertice& vertice)
{
    ProtoAddress addr;
    addr.SetRawHostAddress(ProtoAddress::IPv4, vertice.GetKey(), 4);
    // On first insert, init tree according to vertice key length (in bits)
    // (we're assuming a single fixed key length for now)
    if (!ptree.IsReady())
    {
        unsigned int keyBits = vertice.GetKeyLength();
        if (!ptree.Init(keyBits, keyBits))
        {
            DMSG(0, "ProtoGraph::InsertVertice() ptree.Init() error\n");
            return false; 
        }
    }
    // Get a ProtoTree::Item to use as container
    ProtoTree::Item* item = GetItemFromPool();
    if (NULL == item)
    {
        DMSG(0, "ProtoGraph::InsertNode() GetItemFromPool() error\n");
        return false;      
    }
    // Embed vertice into ProtoTree::Item container
    item->Init(vertice.GetKey(), vertice.GetKeyLength(), &vertice);
    ptree.Insert(item);
    return true;
}  // end ProtoGraph::InsertNode()

void ProtoGraph::RemoveVertice(Vertice& vertice)
{
    ProtoTree::Item* item = ptree.Find(vertice.GetKey(), vertice.GetKeyLength());
    if (NULL != item)
    {
        item = ptree.Remove(item);
        ReturnItemToPool(*item); 
    }                                  
}  // end ProtoGraph::RemoveNode()

ProtoTree::Item* ProtoGraph::GetItemFromPool()
{
    ProtoTree::Item* item = item_pool.Get();
    if (NULL == item)
    {
        unsigned int add = (0 != item_pool_depth) ? item_pool_depth : POOL_DEPTH_MIN;
        for (unsigned int i = 0; i < add; i++)
        {
            item = new ProtoTree::Item;
            if (NULL != item)
            {
                item_pool.Put(*item); 
                item_pool_depth++;
                item_pool_count++;
            }
            else
            {
                DMSG(0, "ProtoGraph::GetItemFromPool() new ProtoTree::Item error: %s\n", GetErrorString());
                break;    
            }   
            
        }
        item = item_pool.Get();
        if (NULL == item) return NULL;
    }
    item_pool_count--;
    return item;  
}  // end ProtoGraph::GetItemFromPool()

void ProtoGraph::ReturnItemToPool(ProtoTree::Item& item)
{
    item_pool.Put(item);
    item_pool_count++;
    unsigned int outstanding = item_pool_depth - item_pool_count;
    // Free some pool items if not much is being used.  (TBD) revisit this
    if ((outstanding < (item_pool_count >> 1)) && (item_pool_depth > POOL_DEPTH_MIN)) 
    {
        for (unsigned int i = 0 ; i < outstanding; i++)
            delete item_pool.Get();
        item_pool_depth -= outstanding;
        item_pool_count -= outstanding;
    }
}  // end ProtoGraph::ReturnItemToPool()

ProtoGraph::VerticeIterator::VerticeIterator(ProtoGraph& nodeTree)
  : ProtoTree::Iterator(nodeTree.ptree)
{
}

ProtoGraph::VerticeIterator::~VerticeIterator()
{
}

ProtoGraph::Traversal::Traversal(ProtoGraph&    theGraph, 
                                 Vertice&       startVertice,
                                 bool           depthFirst)
 : vertice_tree(theGraph), start_vertice(startVertice), 
   depth_first(depthFirst), current_level(0), trans_vertice(NULL)
{
    Reset();
}

ProtoGraph::Traversal::~Traversal()
{
}

void ProtoGraph::Traversal::Reset()
{
    queue.Empty();
    // Visit every node in graph and mark as unvisited
    VerticeIterator verticeIterator(vertice_tree);
    Vertice* nextVertice;
    while ((nextVertice = verticeIterator.GetNextVertice()))
    {
        if (nextVertice == &start_vertice)
            nextVertice->SetVisited(true);
        else
            nextVertice->SetVisited(false);
    }
    queue.Append(start_vertice);
    trans_vertice = &start_vertice;
    current_level = 0;
}  // end ProtoGraph::Traversal::Reset()

ProtoGraph::Vertice* ProtoGraph::Traversal::GetNextVertice(unsigned int* level)
{
    Vertice* currentVertice = queue.RemoveHead();
    if (NULL != currentVertice)
    {
        // Iterate through edges, enqueue "unvisited" vertices
        // for future visitation (breadth first search)
        ProtoGraph::Vertice::EdgeIterator edgeIterator(*currentVertice);
        Edge* nextEdge;
        Edge* firstEdge = NULL;
        while ((nextEdge = edgeIterator.GetNextEdge()))
        {
            Vertice& nextVertice = nextEdge->GetDst(*currentVertice);
            if (!nextVertice.WasVisited())
            {
                // unvisited vertice
                if (depth_first)
                    queue.Prepend(nextVertice);
                else
                    queue.Append(nextVertice);
                nextVertice.SetVisited(true);
                if (NULL == firstEdge) firstEdge = nextEdge;
            }
        }
        // Track depth in search tree as search progresses ...
        if (NULL == trans_vertice)
        {
            trans_vertice = firstEdge ? &firstEdge->GetDst(*currentVertice) : NULL;
        }
        else if (trans_vertice == currentVertice)
        {
            trans_vertice = firstEdge ? &firstEdge->GetDst(*currentVertice) : NULL; 
            current_level++;  
        }
        if (NULL != level) *level = current_level;
    }
    return currentVertice;
}  // end ProtoGraph::Traversal::GetNextVertice()
