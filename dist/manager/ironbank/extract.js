"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.extractPackageFile = void 0;
const is_1 = __importDefault(require("@sindresorhus/is"));
const url_1 = require("url");
const js_yaml_1 = __importDefault(require("js-yaml"));
const logger_1 = require("../../logger");
const datasourceDocker = __importStar(require("../../datasource/docker"));
const datasourceGithubReleases = __importStar(require("../../datasource/github-releases"));
const dockerVersioning = __importStar(require("../../versioning/docker"));
function parseUrl(urlString) {
    // istanbul ignore if
    if (!urlString) {
        return null;
    }
    const url = url_1.parse(urlString);
    if (url.host !== 'github.com') {
        return null;
    }
    const path = url.path.split('/').slice(1);
    const repo = path[0] + '/' + path[1];
    let currentValue = null;
    if (path[2] === 'releases' && path[3] === 'download') {
        currentValue = path[4];
    }
    if (path[2] === 'archive') {
        currentValue = path[3].replace(/\.tar\.gz$/, '');
    }
    if (currentValue) {
        return { repo, currentValue };
    }
    // istanbul ignore next
    return null;
}
function extractPackageFile(content) {
    const deps = [];
    let download;
    try {
        download = js_yaml_1.default.safeLoad(content, { json: true });
    }
    catch (err) {
        logger_1.logger.debug('Failed to parse download.yaml');
        return null;
    }
    if (!(download && is_1.default.array(download.resources))) {
        logger_1.logger.debug('download.yaml has no dependencies');
        return null;
    }
    for (const item of download.resources) {
        const dep = { managerData: { item } };
        if (item.url) {
            // docker
            if (item.url.startsWith('docker://')) {
                const [currentDepTag, currentDigest] = item.url.split('@');
                const [lookupName, currentValue] = item.tag.split(':');
                dep.depType = 'ironbank-docker';
                dep.depName = lookupName;
                dep.datasource = datasourceDocker.id;
                dep.versioning = dockerVersioning.id;
                dep.lookupName = lookupName;
                dep.currentDigest = currentDigest;
                dep.currentValue = currentValue;
                deps.push(dep);
            }
            // github-releases
            else if (item.url.includes('github.com')) {
                const parsedUrl = parseUrl(item.url);
                dep.depType = 'ironbank-github';
                dep.depName = parsedUrl.repo;
                dep.repo = parsedUrl.repo;
                dep.currentValue = parsedUrl.currentValue;
                dep.datasource = datasourceGithubReleases.id;
                dep.lookupName = dep.repo;
                deps.push(dep);
            }
        }
    }
    if (!deps.length) {
        return null;
    }
    return { deps };
}
exports.extractPackageFile = extractPackageFile;
//# sourceMappingURL=extract.js.map