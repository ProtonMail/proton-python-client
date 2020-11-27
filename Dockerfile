FROM IMAGE_URL
RUN apt-get update
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata

# Install a few useful packages

RUN apt-get install -y net-tools \
    apt-utils \
    iproute2 \
    python3 \
    network-manager \
    network-manager-openvpn \
    sudo \
    vim \
    pkg-config \
    iputils-ping \
    openvpn \
    libssl-dev

RUN apt-get install -y \
    python3-pip \
    python3-xdg \
    python3-keyring \
    python3-jinja2 \
    python3-dialog \
    python3-pytest \
    python3-distro \
    libcairo2-dev \
    libgirepository1.0-dev \
    gir1.2-nm-1.0

RUN python3 -m pip install cython && \
    python3 -m pip install proton-client && \
    python3 -m pip install keyring && \
    python3 -m pip install pytest-cov && \
    python3 -m pip install --upgrade sentry-sdk==0.10.2

COPY requirements.txt /tmp
RUN python3 -m pip install -r /tmp/requirements.txt && \
    true

RUN apt-get install -y \
    dbus-x11 \
    libsecret-tools \
    gnome-keyring

RUN useradd -ms /bin/bash user
RUN usermod -a -G sudo user
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

COPY docker_entry.sh /usr/local/bin
COPY __SOURCE_APP /home/user/proton-python-client

RUN chown -R user:user /home/user/proton-python-client
WORKDIR /home/user/proton-python-client

ENTRYPOINT ["/usr/local/bin/docker_entry.sh"]
