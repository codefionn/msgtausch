# Container Registry CI/CD Setup

## Required Secrets

To enable Docker Hub and Quay.io publishing in the CI/CD pipeline, you need to set up the following secrets in your GitHub repository:

### Docker Hub Secrets

#### 1. DOCKERHUB_USERNAME
- Go to your repository on GitHub
- Navigate to Settings → Secrets and variables → Actions
- Click "New repository secret"
- Name: `DOCKERHUB_USERNAME`
- Value: Your Docker Hub username

#### 2. DOCKERHUB_TOKEN
- Log in to Docker Hub
- Go to Account Settings → Security
- Click "New Access Token"
- Create a token with appropriate permissions (Read, Write, Delete)
- Copy the generated token
- Go to your GitHub repository
- Navigate to Settings → Secrets and variables → Actions
- Click "New repository secret"
- Name: `DOCKERHUB_TOKEN`
- Value: The access token you just created

### Quay.io Secrets

#### 3. QUAY_USERNAME
- Go to your repository on GitHub
- Navigate to Settings → Secrets and variables → Actions
- Click "New repository secret"
- Name: `QUAY_USERNAME`
- Value: Your Quay.io username/organization

#### 4. QUAY_TOKEN
- Log in to Quay.io
- Go to Account Settings → Generate Encrypted Password or Robot Accounts
- Create a robot account or use an encrypted password with write permissions
- Copy the generated token/password
- Go to your GitHub repository
- Navigate to Settings → Secrets and variables → Actions
- Click "New repository secret"
- Name: `QUAY_TOKEN`
- Value: The robot token or encrypted password

## Container Image Publishing

The CI/CD pipeline will automatically publish to both registries:

### On main branch pushes:
- Build and push development images tagged as:
  - **Docker Hub**: `{username}/msgtausch:main` and `{username}/msgtausch:latest`
  - **Quay.io**: `quay.io/{username}/msgtausch:main` and `quay.io/{username}/msgtausch:latest`

### On version tags (v*):
- Build and push release images tagged as:
  - **Docker Hub**: 
    - `{username}/msgtausch:v1.2.3` (exact version)
    - `{username}/msgtausch:1.2.3` (semver)
    - `{username}/msgtausch:1.2` (major.minor)
    - `{username}/msgtausch:1` (major only)
  - **Quay.io**: 
    - `quay.io/{username}/msgtausch:v1.2.3` (exact version)
    - `quay.io/{username}/msgtausch:1.2.3` (semver)
    - `quay.io/{username}/msgtausch:1.2` (major.minor)
    - `quay.io/{username}/msgtausch:1` (major only)

## Multi-Platform Support

Images are built for:
- `linux/amd64`
- `linux/arm64`

## Security Notes

- Never commit container registry credentials to the repository
- Use access tokens/robot accounts instead of passwords
- Regularly rotate your access tokens and robot accounts
- Set appropriate permissions on tokens (minimum required for read/write)
- For Quay.io, robot accounts are recommended over personal access tokens for CI/CD