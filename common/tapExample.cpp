#include "protokit.h"

#include <stdio.h>
#include <ctype.h>  // for "isspace()" 

int main(int argc, char* argv[])
{
    SetDebugLevel(PL_INFO);  // output "PL_INFO" messages and lower (PL_WARN, PL_ERROR, etc)
    
    if (argc < 3)
    {
        fprintf(stderr, "tapExample Usage: tapExample <tapName> <smfName>\n");
        return -1;
    }
    
    // The ProtoPipe we _listen_ to
    ProtoPipe tap_pipe(ProtoPipe::MESSAGE);
    // The ProtoPipe we send to
    ProtoPipe smf_pipe(ProtoPipe::MESSAGE);
    
    // 1) "Listen" to our pipe
    const char* tapName = argv[1];
    if (!tap_pipe.Listen(tapName))
    {
        fprintf(stderr, "tapExample error: unable to open pipe named \"%s\"\n", tapName);
        return -1;
    }
    
    // 2) Attempt to "connect" to SMF pipe
    //    (note it might not be open if launched second)
    //    (nrlsmf launched with "tap" command will contact us w/ "smfClientStart" (see below))
    const char* smfName = argv[2];
    if (smf_pipe.Connect(smfName))
    {
        // Tell nrlsmf instance our tap name
        char buffer[256];
        sprintf(buffer, "tap %s", tapName);
        unsigned int numBytes = strlen(buffer)+1;
        if (!smf_pipe.Send(buffer, numBytes))
        {
            DMSG(0, "SmfApp::OnCommand(tap) error sending 'tap' command to 'nrlsmf' process \"%s\"\n", smfName);
            tap_pipe.Close();
            return -1;  
        }  
    }
    else
    {
        PLOG(PL_WARN, "tapExample warning: unable to connect to nrlsmf instance \"%s\"\n", smfName);
    }
    
    // 3) Since we're not doing async I/O here, we can make a blocking call to ProtoPipe::Recv()
    //    to listen for "instructions" from an nrlsmf instance
    int exitStatus = 0;
    while (true)
    {
        char buffer[8192];
        unsigned int numBytes = 8192;
        if (!tap_pipe.Recv(buffer, numBytes))
        {
            fprintf(stderr, "tapExample error: ProtoPipe::Recv() error\n");
            exitStatus = -1;
            break;
        }  
        if (0 == numBytes)
        {
            PLOG(PL_WARN, "tapExample warning: received ZERO byte message on 'tap_pipe'\n");
            continue;
        }
        if (!strncmp("smfClientStart", buffer, 14))
        {
            if (smf_pipe.IsOpen()) smf_pipe.Close();
            // Make sure it is '\0' terminated
            buffer[8191] = '\0';
            buffer[numBytes] = '\0';
            // Point 'smfName' to argument of 'smfClientStart' command, skipping leading white space 
            char* smfName = buffer + 14;
            while (isspace(*smfName)) smfName++;
            if (!smf_pipe.Connect(smfName))
            {
                PLOG(PL_WARN, "tapExample warning: received invalid 'smfClientStart' command\n");
                continue;
            }
            PLOG(PL_INFO, "tapExample: received 'smfClientStart' from  instance \"%s\"\n", smfName);
        }
        else if (!strncmp("smfPkt ", buffer, 7))
        {
            // "Process" a packet from SMF process
            // First byte following "smfPkt " header is "indexCount"
            unsigned int indexCount = (unsigned int)buffer[7];
            if (0 == indexCount)
            {
                PLOG(PL_ERROR, "tapExample error: received 'smfPkt' with ZERO indexCount\n");
                continue;
            }
            // Pointer to list of iface indices (first index is "srcIndex")
            UINT8* indexPtr = (UINT8*)(buffer + 8);
            unsigned int srcIndex = indexPtr[0];
            char* framePtr = (char*)(indexPtr + indexCount);
            // frame length (bytes)  = msgLen - 7 "smfPkt " bytes - 1 indexCount byte - <indexCount value>
            unsigned int frameLength = numBytes - 7 - 1 - indexCount; 
            fprintf(stderr, "tapExample: received %u byte frame from SMF process\n", frameLength);
            // Echo "smfPkt" back to "nrlsmf"
            if (!smf_pipe.Send(buffer, numBytes))
                PLOG(PL_ERROR, "tapExample error: unable to send smfPkt msg to SMF process\n");
        }
        else
        {
            PLOG(PL_WARN, "tapExample warning: received unknown message type on 'tap_pipe'\n");
        }
    }  // end while (running)
    
    if (smf_pipe.IsOpen())
    {
        const char* buffer = "tap off";
        unsigned int numBytes = strlen(buffer) + 1;
        if (!smf_pipe.Send(buffer, numBytes))
            PLOG(PL_WARN, "tapExample warning: unable to send 'tap off' message to SMF process\n");
        smf_pipe.Close();
    }
    tap_pipe.Close();
    
    return exitStatus;
}  // end main()
