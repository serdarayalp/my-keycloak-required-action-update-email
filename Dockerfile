# Dockerfile
FROM quay.io/keycloak/keycloak:23.0.3

# Set the working directory
WORKDIR /opt/keycloak

# Copy deployments to the image
COPY ./deployments /opt/keycloak/providers

# Define environment variables
ENV KEYCLOAK_ADMIN=admin \
    KEYCLOAK_ADMIN_PASSWORD=admin \
    KC_FEATURES=update-email \
    KEYCLOAK_LOGLEVEL=INFO \
    ROOT_LOGLEVEL=INFO \
    KC_HTTP_RELATIVE_PATH="/auth"

# Command to start Keycloak in dev mode
CMD ["start-dev"]

# Expose ports
EXPOSE 8080
