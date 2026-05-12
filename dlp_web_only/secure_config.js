"""
===============================================================================
SECURE CONFIG LOADER - NODE.JS VERSION
===============================================================================
Safely load and manage environment variables and secrets for Node.js applications.
This module ensures that secrets are never hardcoded and provides a secure,
centralized way to access configuration values.

Installation:
    npm install dotenv

Usage:
    const config = require('./secure_config.js');
    const apiKey = config.getSecret('API_KEY');
    const port = config.getInt('SERVER_PORT', 3000);

===============================================================================
SECURITY BEST PRACTICES IMPLEMENTED:
===============================================================================
1. ✓ Loads secrets from .env files (never hardcoded)
2. ✓ Validates required secrets are present
3. ✓ Never logs or prints secret values
4. ✓ Provides typed access to configuration values
5. ✓ Supports multiple environment files (.env, .env.local, etc.)
6. ✓ Validates configuration on startup
7. ✓ Type safety with JSDoc
8. ✓ Clear error messages when secrets are missing

===============================================================================
"""

const fs = require('fs');
const path = require('path');

/**
 * Custom error class for configuration errors
 */
class ConfigurationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'ConfigurationError';
    }
}

/**
 * Secure configuration manager for loading environment variables from .env files.
 * 
 * Features:
 * - Loads from .env files with proper precedence
 * - Validates required secrets are present
 * - Provides type-safe access to configuration
 * - Never logs secret values
 * - Supports environment-specific configurations
 */
class SecureConfig {
    /**
     * Initialize configuration loader
     * @param {string[]} envFiles - List of .env file paths to load
     */
    constructor(envFiles = null) {
        this.envFiles = envFiles || this._getDefaultEnvFiles();
        this.loaded = false;
        this.config = {};
        
        this._loadEnvFiles();
        this._validateConfiguration();
    }

    /**
     * Get default .env file locations in order of precedence
     * Later files override earlier ones.
     * @returns {string[]} Array of .env file paths
     */
    _getDefaultEnvFiles() {
        const env = process.env.NODE_ENV || 'development';
        const baseDir = __dirname;

        return [
            path.join(baseDir, '.env'),
            path.join(baseDir, `.env.${env}`),
            path.join(baseDir, '.env.local'),
        ].filter(file => fs.existsSync(file));
    }

    /**
     * Load environment variables from .env files
     * @private
     */
    _loadEnvFiles() {
        if (this.envFiles.length === 0) {
            console.warn(
                '⚠️  No .env files found. Create .env file with required secrets. ' +
                'See .env.example for template.'
            );
            return;
        }

        this.envFiles.forEach(envFile => {
            try {
                const content = fs.readFileSync(envFile, 'utf8');
                this._parseEnvFile(content);
                console.log(`✓ Loaded configuration from: ${envFile}`);
            } catch (error) {
                throw new ConfigurationError(
                    `Failed to load ${envFile}: ${error.message}`
                );
            }
        });

        this.loaded = true;
    }

    /**
     * Parse .env file content into key-value pairs
     * @param {string} content - Content of .env file
     * @private
     */
    _parseEnvFile(content) {
        const lines = content.split('\n');

        lines.forEach(line => {
            // Skip empty lines and comments
            line = line.trim();
            if (!line || line.startsWith('#')) return;

            // Parse KEY=VALUE
            const [key, ...valueParts] = line.split('=');
            if (!key) return;

            let value = valueParts.join('=').trim();

            // Remove surrounding quotes if present
            if ((value.startsWith('"') && value.endsWith('"')) ||
                (value.startsWith("'") && value.endsWith("'"))) {
                value = value.slice(1, -1);
            }

            this.config[key.trim()] = value;
            process.env[key.trim()] = value;
        });
    }

    /**
     * Validate that all required secrets are present
     * @private
     */
    _validateConfiguration() {
        const env = process.env.NODE_ENV || 'development';
        const requiredSecrets = ['API_KEY', 'JWT_SECRET'];

        if (env === 'production') {
            // Production might require additional secrets
            const productionRequired = [
                'API_KEY',
                'JWT_SECRET',
                'DATABASE_URL',
            ];
            requiredSecrets.push(...productionRequired);
        }

        const missing = requiredSecrets.filter(
            secret => !process.env[secret] && !this.config[secret]
        );

        if (missing.length > 0) {
            throw new ConfigurationError(
                `Missing required environment variables in ${env} mode: ` +
                `${missing.join(', ')}\n` +
                `Instructions:\n` +
                `  1. Copy .env.example to .env\n` +
                `  2. Fill in actual values for: ${missing.join(', ')}\n` +
                `  3. Never commit .env to version control`
            );
        }
    }

    /**
     * Get a configuration value as string
     * @param {string} key - Environment variable name
     * @param {string} [defaultValue] - Default value if not found
     * @returns {string|null} Configuration value or default
     * @throws {ConfigurationError} If key is required and not found
     */
    get(key, defaultValue = null) {
        const value = process.env[key] || this.config[key] || defaultValue;
        return value || null;
    }

    /**
     * Get a secret value securely
     * @param {string} key - Environment variable name for the secret
     * @param {boolean} [required=false] - If true, raises error if secret is missing
     * @returns {string|null} Secret value
     * @throws {ConfigurationError} If required=true and secret is missing
     */
    getSecret(key, required = false) {
        const value = process.env[key] || this.config[key];

        if (!value && required) {
            throw new ConfigurationError(
                `Required secret '${key}' not found in environment. ` +
                `Please set it in your .env file.`
            );
        }

        return value || null;
    }

    /**
     * Get a configuration value as integer
     * @param {string} key - Environment variable name
     * @param {number} [defaultValue] - Default value if not found
     * @returns {number} Configuration value as integer
     * @throws {ConfigurationError} If value cannot be converted to integer
     */
    getInt(key, defaultValue = null) {
        const value = process.env[key] || this.config[key];

        if (!value) {
            if (defaultValue !== null) return defaultValue;
            throw new ConfigurationError(`Configuration '${key}' not found`);
        }

        const parsed = parseInt(value, 10);
        if (isNaN(parsed)) {
            throw new ConfigurationError(
                `Configuration '${key}' must be an integer, got: ${value}`
            );
        }

        return parsed;
    }

    /**
     * Get a configuration value as boolean
     * @param {string} key - Environment variable name
     * @param {boolean} [defaultValue=false] - Default value if not found
     * @returns {boolean} Configuration value as boolean
     */
    getBoolean(key, defaultValue = false) {
        const value = (process.env[key] || this.config[key] || String(defaultValue)).toLowerCase();
        return ['true', '1', 'yes', 'on'].includes(value);
    }

    /**
     * Get a configuration value as array (comma-separated)
     * @param {string} key - Environment variable name
     * @param {string} [delimiter=','] - Delimiter to split the value
     * @param {string[]} [defaultValue=[]] - Default array if not found
     * @returns {string[]} Configuration value split as array
     */
    getArray(key, delimiter = ',', defaultValue = []) {
        const value = process.env[key] || this.config[key];

        if (!value) {
            return defaultValue;
        }

        return value
            .split(delimiter)
            .map(item => item.trim())
            .filter(item => item.length > 0);
    }

    /**
     * Validate that required keys are present
     * @param {string[]} keys - List of required environment variable names
     * @throws {ConfigurationError} If any required key is missing
     */
    validateRequired(keys) {
        const missing = keys.filter(
            key => !(process.env[key] || this.config[key])
        );

        if (missing.length > 0) {
            throw new ConfigurationError(
                `Missing required configuration: ${missing.join(', ')}`
            );
        }
    }

    /**
     * Get all configuration (excluding secrets for safety)
     * @returns {object} Current configuration
     */
    getAll() {
        // Filter out sensitive keys
        const sensitiveKeys = [
            'API_KEY', 'SECRET_KEY', 'PASSWORD', 'TOKEN', 'JWT_SECRET',
            'DATABASE_PASSWORD', 'SMTP_PASSWORD', 'AWS_SECRET_ACCESS_KEY'
        ];

        const filtered = {};
        Object.entries(process.env).forEach(([key, value]) => {
            if (!sensitiveKeys.some(sensitive => key.includes(sensitive))) {
                filtered[key] = value;
            }
        });

        return filtered;
    }

    /**
     * String representation without exposing secrets
     * @returns {string} String representation
     */
    toString() {
        const env = process.env.NODE_ENV || 'development';
        return (
            `<SecureConfig ` +
            `environment=${env} ` +
            `loaded_files=${this.envFiles.length} ` +
            `validation_passed=true>`
        );
    }
}

/**
 * Initialize Express app with secure configuration
 * @param {object} app - Express application instance
 */
function initSecureConfig(app) {
    try {
        // Set Express configuration from environment
        app.set('secret', config.getSecret('JWT_SECRET', false));
        app.set('env', process.env.NODE_ENV || 'development');
        app.set('trust proxy', config.getBoolean('TRUST_PROXY', false));

        // Security headers middleware
        app.use((req, res, next) => {
            res.set('X-Content-Type-Options', 'nosniff');
            res.set('X-Frame-Options', 'DENY');
            res.set('X-XSS-Protection', '1; mode=block');
            next();
        });

        console.log('✓ Express app configured securely');
    } catch (error) {
        console.error(`Failed to initialize Express config: ${error.message}`);
        throw error;
    }
}

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================
let config;

try {
    config = new SecureConfig();
    console.log('✓ Configuration loaded successfully');
} catch (error) {
    console.error(`✗ Configuration Error: ${error.message}`);
    process.exit(1);
}

// ============================================================================
// EXPORTS
// ============================================================================
module.exports = {
    config,
    ConfigurationError,
    SecureConfig,
    initSecureConfig,
};

// ============================================================================
// EXAMPLE USAGE
// ============================================================================
if (require.main === module) {
    try {
        console.log('Loading configuration...\n');

        // Access various configuration types
        const apiKey = config.getSecret('API_KEY', true);
        console.log('✓ API Key loaded (value hidden for security)');

        const port = config.getInt('PORT', 3000);
        console.log(`✓ Server Port: ${port}`);

        const debug = config.getBoolean('DEBUG', false);
        console.log(`✓ Debug Mode: ${debug}`);

        const paths = config.getArray('MONITORED_PATHS');
        console.log(`✓ Monitored Paths: ${paths.length > 0 ? paths.join(', ') : 'none'}`);

        console.log('\n✓ All configurations loaded successfully!');
    } catch (error) {
        console.error(`✗ Configuration Error: ${error.message}`);
        process.exit(1);
    }
}
