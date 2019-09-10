
// The purpose of this program is to test the ManetGraph
// classes that will be used for SMF relay set determination
// in the near future

#include "manetGraph.h"

#include <protoDebug.h>
#include <protoDefs.h>

#include <stdio.h>   // for sprintf()
#include <stdlib.h>  // for rand(), srand()

int main(int argc, char* argv[])
{
    struct timeval currentTime;
    ProtoSystemTime(currentTime);
    srand(currentTime.tv_usec);
    
    ManetGraph theGraph;
    ManetGraph::Node* srcNode;
    
    // Add N nodes to theGraph
    const int NUM_NODES = 63;
    for (int i = 0 ; i < NUM_NODES; i++)
    {
        char host[32];
        int c = i / 256;
        int d = i % 256;
        sprintf(host, "192.168.%d.%d", c, d);
        ProtoAddress addr;   
        addr.ResolveFromString(host);
        ManetGraph::Node* node = new ManetGraph::Node(addr);
        theGraph.InsertNode(*node);
        if (0 == i) srcNode = node;
    }
    
    int COST_MAX = 8;
    
    // Randomly connect nodes until topology is fully connected
    /*while (1)        
    {
        ManetGraph::Cost linkCost;
        double cv = 1.0;//rand() % COST_MAX;
        if (cv < 1.0) cv = COST_MAX;
        linkCost.SetValue(cv);
        int a = rand() % NUM_NODES;
        int b = rand() % NUM_NODES;
        if (a == b) continue;
        char host[32];
        sprintf(host, "192.168.%d.%d", a/256, a%256);
        ProtoAddress addr;
        addr.ResolveFromString(host);
        ManetGraph::Node * node = theGraph.FindNode(addr);
        ASSERT(node);
        ManetGraph::Interface& ifaceA = node->GetDefaultInterface();
        sprintf(host, "192.168.%d.%d", b/256, b%256);
        addr.ResolveFromString(host);
        node = theGraph.FindNode(addr);
        ManetGraph::Interface& ifaceB = node->GetDefaultInterface();
        
        ifaceA.Connect(ifaceB, linkCost);
        
        // (TBD) "Update()" Dijkstra only when link added reduces cost
        
        // Do Dijkstra traversal and count connected links
        // (break when we have a fully connected graph)
        unsigned int ifaceCount = 0;
        ManetGraph::DijkstraTraversal dijkstra(theGraph, *srcNode);
        ManetGraph::Interface* iface;
        while (NULL != (iface = dijkstra.GetNextInterface()))
        {
            ifaceCount++;
        }
        if (ifaceCount == NUM_NODES) break;
    }*/
     
    // Build an ordered pyramid 
    for (unsigned int i = 0; i < NUM_NODES/2; i++)
    {
        ManetGraph::Cost linkCost;
        double cv = 1.0;//rand() % COST_MAX;
        if (cv < 1.0) cv = COST_MAX;
        linkCost.SetValue(cv);
        
        ProtoAddress addr;
        char host[32];
        sprintf(host, "192.168.%d.%d", i/256, i%256);
        addr.ResolveFromString(host);
        ManetGraph::Node * node = theGraph.FindNode(addr);
        ASSERT(node);
        ManetGraph::Interface& ifaceA = node->GetDefaultInterface();
        
        for (unsigned int j = (2*i + 1); j <= (2*i + 2); j++)
        {
            if (j >= NUM_NODES) break;
            sprintf(host, "192.168.%d.%d", j/256, j%256);
            addr.ResolveFromString(host);
            node = theGraph.FindNode(addr);
            ASSERT(node);
            ManetGraph::Interface& ifaceB = node->GetDefaultInterface();
            ifaceA.Connect(ifaceB, linkCost);
        }
    }
    
    // Cost/Queue used to build "pretty" view of the tree
    ManetGraph::Cost maxCost;
    maxCost.Minimize();
    ManetGraph::Interface::PriorityQueue q;
    
    // Do Dijkstra traversal and show "routing table"
    struct timeval startTime, stopTime;
    ProtoSystemTime(startTime);
    
    ManetGraph::DijkstraTraversal dijkstra(theGraph, *srcNode);
    ManetGraph::Interface* iface;
    
   
    while (NULL != (iface = dijkstra.GetNextInterface()))
    {
        //TRACE("gt: traversed to iface:%s cost:%lf ", 
        //      iface->GetAddress().GetHostString(), iface->GetCost().GetValue());
        ManetGraph::Interface* nextHop = iface->GetNextHop(srcNode->GetDefaultInterface());
        //TRACE("nextHop:%s ", nextHop ? nextHop->GetAddress().GetHostString() : "(none)");
        ManetGraph::Interface* prevHop = iface->GetPrevHop();
        //TRACE("prevHop:%s \n", prevHop ? prevHop->GetAddress().GetHostString() : "(none)"); 
        
        if (iface->GetCost() > maxCost) maxCost = iface->GetCost();
        q.Prepend(*iface);       
    }
    ProtoSystemTime(stopTime);
    
    double deltaTime = 1000.0 * (stopTime.tv_sec - startTime.tv_sec);
    if (stopTime.tv_usec > startTime.tv_usec )
        deltaTime += 1.0e-03 * (double)(stopTime.tv_usec - startTime.tv_usec);
    else
        deltaTime -= 1.0e-03 * (double)(stopTime.tv_usec - startTime.tv_usec);
    
    TRACE("deltaTime = %lf msec\n", deltaTime);
    
    
     // Test ManetGraph::DijkstraTraversal::Update()
    ProtoAddress addr;
    addr.ResolveFromString("192.168.0.12");
    ManetGraph::Node* node = theGraph.FindNode(addr);
    ASSERT(node);
    ManetGraph::Interface& ifaceA = node->GetDefaultInterface();
    addr.ResolveFromString("192.168.0.32");
    node = theGraph.FindNode(addr);
    ASSERT(node);
    ManetGraph::Interface& ifaceB = node->GetDefaultInterface();        
    ManetGraph::Cost linkCost;
    linkCost.SetValue(1.0);
    ifaceA.Connect(ifaceB, linkCost);
    dijkstra.Update(ifaceA);
    
    // Now "walk" the resultant routing tree and load into "q" in reverse order
    q.Empty();
    dijkstra.TreeWalkReset();
    while (NULL != (iface = dijkstra.TreeWalkNext()))
    {
        q.Prepend(*iface);
    }
       
    TRACE("performing bfs ...\n");     
    q.Empty();
    ProtoGraph::Traversal bfs(theGraph, srcNode->GetDefaultInterface());
    while (NULL != (iface = static_cast<ManetGraph::Interface*>(bfs.GetNextVertice())))
    {
        q.Prepend(*iface);   
    }
    TRACE("bfs complete.\n");      
    
    
    // Output tree from leaf interfaces (max cost interfaces) upwards
    const int WIDTH_MAX = 300;
    const int HEIGHT_MAX = 300;
    printf("bgbounds 0,%d,%d,0\n", WIDTH_MAX, HEIGHT_MAX);
    unsigned int numLevels = (unsigned int)(maxCost.GetValue() + 0.5) + 1;
    double yStep = (double)HEIGHT_MAX / (double)numLevels;
    double y = yStep / 2.0;
    ManetGraph::Interface::PriorityQueue::Iterator queueIterator(q);
    while (NULL != (iface = queueIterator.GetNextInterface()))
    {
        // 1) Count interfaces at this level  ...
        ManetGraph::Cost theCost = iface->GetCost();
        ManetGraph::Cost nextCost(theCost);
        unsigned int costCount = 1;
        while (NULL != (iface = queueIterator.GetNextInterface()))
        {
            nextCost = iface->GetCost();
            if (nextCost != theCost)
                break;
            else
                costCount++;
        }
        double xStep = (double)WIDTH_MAX / (double)costCount;
        double x = xStep / 2.0;
        for (unsigned int i = 0; i < costCount; i++)
        {
            iface = static_cast<ManetGraph::Interface*>(q.RemoveHead());
            char name[64];
            iface->GetAddress().GetHostString(name, 64);
            char* ptr = strrchr(name, '.');
            ASSERT(ptr);
            ptr += 1;
            printf("node %s pos %d,%d\n", ptr, (int)(x+0.5), (int)(y+0.5));
            x += xStep;
        }
        queueIterator.Reset();
        
        y += yStep * (theCost.GetValue() - nextCost.GetValue());
        
    }
    
    // Iterate over the entire Patricia tree
    // and outputs SDT commands to _link_ nodes
    // "selected" (used for routing) links are colored blue and other links are grey
    ManetGraph::InterfaceIterator ifaceIterator(theGraph);
    while (NULL != (iface = ifaceIterator.GetNextInterface()))
    {
        ManetGraph::Interface::LinkIterator linkIterator(*iface);
        ManetGraph::Link* link;
        while (NULL != (link = linkIterator.GetNextLink()))
        {
            ManetGraph::Interface* parent = iface->GetPrevHop();
            ManetGraph::Interface& dst = link->GetDst(*iface);
            char ifaceName[64], dstName[64];
            iface->GetAddress().GetHostString(ifaceName, 64);
            dst.GetAddress().GetHostString(dstName, 64);
            char* ifaceNamePtr = strrchr(ifaceName, '.');
            char* dstNamePtr = strrchr(dstName, '.');
            ASSERT((NULL != ifaceNamePtr) && (NULL != dstNamePtr));
            ifaceNamePtr += 1;
            dstNamePtr += 1;
            
            bool selected = false;
            ManetGraph::Interface* p = dst.GetPrevHop();
            if ((p == iface) || (parent == &dst)) selected = true;
            
            const char* color = selected ? "blue" : "\"light gray\"";
            int thick = selected ? 2 : 1;
            printf("link %s,%s,%s,%d\n", ifaceNamePtr, dstNamePtr, color, thick);
        }
    }

}  // end main()
