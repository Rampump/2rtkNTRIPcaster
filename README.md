# 2rtkNTRIPcaster

## Introduction
2rtkNTRIPcaster is a NTRIP (Networked Transport of RTCM via Internet Protocol) caster designed to facilitate the distribution of GNSS (Global Navigation Satellite System) correction data over the internet. This project, developed by 2RTK, aims to provide a reliable and efficient solution for data transmission in the field of geospatial positioning.

## Features
- **Data Upload and Broadcasting**: Supports data sources to upload RTCM data through `SOURCE` requests and broadcasts the data to all clients subscribed to the corresponding mount points.
- **Client Authentication and Data Download**: Authenticates clients through `GET` requests, ensuring that only authorized users can download data. Allows multiple users to access concurrently, with a maximum of 3 sessions per user.
- **Mount Point Management**: Configurable list of allowed mount points, enabling data upload and download only for specified mount points. Provides a query function for the list of available mount points.
- **Logging and Monitoring**: Records important events during system operation, such as client connections, authentication results, and data transmission exceptions. Regularly cleans up expired RTCM data to prevent excessive memory usage.

## Installation
1. **Clone the Repository**
    ```bash
    git clone https://github.com/Rampump/2rtkNTRIPcaster.git
    cd 2rtkNTRIPcaster
    ```
2. **Configure the Project**
    - Edit the `config.ini` file to set the allowed mount points, upload password, download user information, server listening address, and port.
    - Create a `mount.txt` file listing the available mount points.
    ```ini
    [General]
    ALLOWED_MOUNTPOINT = mount1
    UPLOAD_PASSWORD = your_upload_password
    MOUNTPOINT_FILE = mount.txt

    [DownloadUsers]
    user1 = password1
    user2 = password2

    [Server]
    HOST = 0.0.0.0
    PORT = 2101
    ```
3. **Start the Server**
    ```bash
    python3 caster.py
    ```

## Usage
### Data Source Upload
Use a device or software that supports the NTRIP protocol to send an upload request to the server. The request should include the correct upload password and mount point.

### Client Data Download
Clients can send a `GET` request to the server to request data from a specific mount point. They need to provide valid authentication information in the request headers.

### Query Mount Point List
Clients can send a `GET` request to the root path (`/`) to obtain the list of available mount points.

## Configuration File Explanation
The `config.ini` file contains the following configuration items:
- **[General] Section**
    - `ALLOWED_MOUNTPOINT`: A comma-separated list of allowed mount points.
    - `UPLOAD_PASSWORD`: The password for data source uploads.
    - `MOUNTPOINT_FILE`: The path to the file containing the list of mount points.
- **[DownloadUsers] Section**
    - Stores the usernames and passwords of download users in the format `username = password`.
- **[Server] Section**
    - `HOST`: The server's listening address.
    - `PORT`: The server's listening port.

## License
This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

## Contribution
Contributions to this project are welcome. Please fork the repository, make your changes, and submit a pull request.

## Contact
If you have any questions or suggestions, please feel free to contact us.
