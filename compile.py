import os

os.system("mkdir -p build && \
          cd build && \
          cmake ../src && \
          make && \
          cp ./scan_util ../"
         )

