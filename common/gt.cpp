
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
    const int NUM_NODES = 100;
    TRACE("gt: Adding %d nodes to graph ...\n", NUM_NODES);
    for (int i = 0 ; i < NUM_NODES; i++)
    {
        char host[32];
        int c = i / 256;
        int d = i % 256;
        sprintf(host, "192.168.%d.%d", c, d);
        ProtoAddress addr;   
        addr.ResolveFromString(host);
        ManetGraph::Node* node = new ManetGraph::Node;
        ManetGraph::Interface* iface = new ManetGraph::Interface(*node, addr);
        node->AppendInterface(*iface);
        
        theGraph.InsertNode(*node);
        //TRACE("   inserted node w/ iface addr %s\n", addr.GetHostString());
        if (0 == i) srcNode = node;
    }
    
    int COST_MAX = 4;
#define MESH
#ifdef MESH
    // Randomly connect nodes until topology is fully connected
    TRACE("gt:  building random mesh ...\n");
    while (1)        
    {
        double cv = rand() % 2 + 1;
        if (cv > 1.0) cv += 6;
        ManetGraph::SimpleCostDouble linkCost(cv);
        int a = rand() % NUM_NODES;
        int b = rand() % NUM_NODES;
        if (a == b) continue;
        char host[32];
        sprintf(host, "192.168.%d.%d", a/256, a%256);
        ProtoAddress addr;
        addr.ResolveFromString(host);
        ManetGraph::Interface* ifaceA = theGraph.FindInterface(addr);
        ASSERT(NULL != ifaceA);
        sprintf(host, "192.168.%d.%d", b/256, b%256);
        addr.ResolveFromString(host);
        ManetGraph::Interface* ifaceB = theGraph.FindInterface(addr);
        ASSERT(NULL != ifaceB);
        
        //TRACE("   connecting iface %s ", ifaceA->GetAddress().GetHostString());
        //TRACE("to iface %s ...\n", ifaceB->GetAddress().GetHostString());
        theGraph.Connect(*ifaceA, *ifaceB, linkCost, true);
        
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
        //TRACE("   ifaceCount : %d\n", ifaceCount);
        if (ifaceCount == NUM_NODES) break;
    }
#else    
    // Build an ordered pyramid 
    TRACE("gt:  building pyramid ...\n");
    for (unsigned int i = 0; i < NUM_NODES/2; i++)
    {
        double cv =  1.0; //rand() % COST_MAX;
        ManetGraph::SimpleCostDouble linkCost(cv);
        
        ProtoAddress addr;
        char host[32];
        sprintf(host, "192.168.%d.%d", i/256, i%256);
        addr.ResolveFromString(host);
        //TRACE("   finding interface w/ addr %s\n", addr.GetHostString());
        ManetGraph::Interface* ifaceA = theGraph.FindInterface(addr);
        ASSERT(NULL != ifaceA);
        
        TRACE("   connecting iface %s to ifaces ", ifaceA->GetAddress().GetHostString());
        for (unsigned int j = (2*i + 1); j <= (2*i + 2); j++)
        {
            if (j >= NUM_NODES) break;
            sprintf(host, "192.168.%d.%d", j/256, j%256);
            addr.ResolveFromString(host);
            ManetGraph::Interface* ifaceB = theGraph.FindInterface(addr);
            ASSERT(NULL != ifaceB);
            TRACE("%s ", ifaceB->GetAddress().GetHostString());
            theGraph.Connect(*ifaceA, *ifaceB, linkCost, false);
        }
        TRACE("\n");
    }
#endif // if/else random mesh/ pyramid  
    
    // Cost/Queue used to build "pretty" view of the tree
    ManetGraph::SimpleCostDouble maxCost;
    maxCost.Minimize();
    ProtoGraph::Vertice::SimpleList q;
    
    // Do Dijkstra traversal and show "routing table"
    TRACE("gt: doing Dijkstra traversal ...\n");
    struct timeval startTime, stopTime;
    ProtoSystemTime(startTime);
    ManetGraph::DijkstraTraversal dijkstra(theGraph, *srcNode);
    ManetGraph::Interface* iface;
    
    while (NULL != (iface = dijkstra.GetNextInterface()))
    {
        const ManetGraph::SimpleCostDouble* scost = dijkstra.GetCost(*iface);
        //TRACE("   traversed to iface:%s cost:%lf ", iface->GetAddress().GetHostString(), scost->GetValue());
        ManetGraph::Interface* nextHop = dijkstra.GetNextHop(*iface);
        
        //TRACE("nextHop:%s ", nextHop ? nextHop->GetAddress().GetHostString() : "(none)");
        ManetGraph::Interface* prevHop = dijkstra.GetPrevHop(*iface);
        //TRACE("prevHop:%s \n", prevHop ? prevHop->GetAddress().GetHostString() : "(none)"); 
        
        const ManetGraph::SimpleCostDouble* dstCost = static_cast<const ManetGraph::SimpleCostDouble*>(dijkstra.GetCost(*iface));
        
        if ((NULL != dstCost) && (*dstCost> maxCost)) 
        {
            maxCost = *dstCost;
        }
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
    /*
    ProtoAddress addr;
    addr.ResolveFromString("192.168.0.12");
    ManetGraph::Interface* ifaceA = theGraph.FindInterface(addr);
    ASSERT(NULL != ifaceA);
    addr.ResolveFromString("192.168.0.32");
    ManetGraph::Interface* ifaceB = theGraph.FindInterface(addr);
    ASSERT(NULL != ifaceB);
    ManetGraph::SimpleCostDouble linkCost(1.0);
    theGraph.Connect(*ifaceA, *ifaceB, linkCost, true);
    dijkstra.Update(*ifaceA);
    */
    /*      
    q.Empty();
    dijkstra.TreeWalkReset();
    while (NULL != (iface = dijkstra.TreeWalkNext()))
    {
        q.Prepend(*iface);
    }
    */
    /*
    TRACE("performing bfs ...\n");     
    q.Empty();
    ProtoGraph::SimpleTraversal bfs(theGraph, srcNode->GetDefaultInterface());
    while (NULL != (iface = static_cast<ManetGraph::Interface*>(bfs.GetNextVertice())))
    {
        const ManetGraph::SimpleCostDouble* c = dijkstra.GetCost(*iface); 
        //TRACE("   prepending %s (cost:%p)...\n", iface->GetAddress().GetHostString(), c);
        q.Prepend(*iface);   
    }
    TRACE("bfs complete.\n");     
    */
    
    // Output tree from leaf interfaces (max cost interfaces) upwards
    const int WIDTH_MAX = 300;
    const int HEIGHT_MAX = 300;
    printf("bgbounds 0,%d,%d,0\n", WIDTH_MAX, HEIGHT_MAX);
    unsigned int numLevels = (unsigned int)(maxCost.GetValue() + 0.5) + 2;
    
    TRACE("NUM LEVELS = %d\n", numLevels);
    double yStep = (double)HEIGHT_MAX / (double)numLevels;
    //double y = yStep / 2.0;
    ProtoGraph::Vertice::SimpleList::Iterator queueIterator(q);
    while (NULL != (iface = static_cast<ManetGraph::Interface*>(queueIterator.GetNextVertice())))
    {
        // 1) Count interfaces at this level  ...
        //TRACE("   getting cost for iface w/ addr %s\n", iface->GetAddress().GetHostString());
        const ManetGraph::SimpleCostDouble* theCost = dijkstra.GetCost(*iface); 
        //if (NULL == theCost) continue;
        ASSERT(NULL != theCost);
        const ManetGraph::SimpleCostDouble* nextCost;
        unsigned int costCount = 1;
        while (NULL != (iface = static_cast<ManetGraph::Interface*>(queueIterator.GetNextVertice())))
        {
            nextCost = static_cast<const ManetGraph::SimpleCostDouble*>(dijkstra.GetCost(*iface)); 
            ASSERT(NULL != nextCost);
            //TRACE("counting ifaces at levels  iface:%s cost:%lf refCost:%lf count:%u comp:%d\n",iface->GetAddress().GetHostString(), 
            //        nextCost->GetValue(), theCost->GetValue(), costCount, (*nextCost != *theCost));
            if (*nextCost != *theCost)
                break;
            else
                costCount++;
        }
        double xStep = (double)WIDTH_MAX / (double)costCount;
        //TRACE("WIDTH_MAX:%d costCount:%d xStep:%lf\n", WIDTH_MAX, costCount, xStep);
        double x = xStep / 2.0;
        double y = HEIGHT_MAX - yStep * (theCost->GetValue() + 1);// - nextCost->GetValue());
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
    }
    
    //TRACE("Iterating over entire graph ...\n");
    
    // Iterate over the entire Patricia tree
    // and outputs SDT commands to _link_ nodes
    // "selected" (used for routing) links are colored blue and other links are grey
    ManetGraph::InterfaceIterator ifaceIterator(theGraph);
    while (NULL != (iface = ifaceIterator.GetNextInterface()))
    {
        ManetGraph::Interface::AdjacencyIterator linkIterator(*iface);
        ManetGraph::Link* link;
        while (NULL != (link = linkIterator.GetNextLink()))
        {
            ManetGraph::Interface* parent = dijkstra.GetPrevHop(*iface);   
            ManetGraph::Interface* dst = link->GetDst();
            ASSERT(NULL != dst);
            char ifaceName[64], dstName[64];
            iface->GetAddress().GetHostString(ifaceName, 64);
            dst->GetAddress().GetHostString(dstName, 64);
            char* ifaceNamePtr = strrchr(ifaceName, '.');
            char* dstNamePtr = strrchr(dstName, '.');
            ASSERT((NULL != ifaceNamePtr) && (NULL != dstNamePtr));
            ifaceNamePtr += 1;
            dstNamePtr += 1;
            
            bool selected = false;
            ManetGraph::Interface* p = dijkstra.GetPrevHop(*dst); 
            if ((p == iface) || (dst == parent)) selected = true;
            
            
            //TRACE("iface: %s ", iface->GetAddress().GetHostString());
            //TRACE("dst: %s ", dst->GetAddress().GetHostString());
            //TRACE("prevHop: %s \n", p ? p->GetAddress().GetHostString() : "(null)");
            
            
            const char* color = selected ? "blue" : "\"light gray\"";
            int thick = (int) static_cast<const ManetGraph::SimpleCostDouble&>(link->GetCost()).GetValue();//selected ? 2 : 1;
            //if (selected)
            //if (dst != parent);
                printf("link %s,%s,%s,%d\n", ifaceNamePtr, dstNamePtr, color, thick);
        }
    }
    
    
    fflush(stdout);
    TRACE("exiting main() ...\n");

}  // end main()

