"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.updateDependency = void 0;
const hasha_1 = require("hasha");
const logger_1 = require("../../logger");
const http_1 = require("../../util/http");
const url_1 = require("url");
const path_1 = __importDefault(require("path"));
const http = new http_1.Http('ironbank');
async function getHashFromFile(url, filename) {
    logger_1.logger.debug("getHashFromFile: " + url + " " + filename);
    try {
        const result = await http.get(url);
        if (result.body) {
            const regex = '(?<hash>[A-Fa-f0-9]{64})\\s+' + filename.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const groups = result.body.match(regex).groups;
            if (groups) {
                return groups.hash;
            }
        }
        return null;
    }
    catch (err) /* istanbul ignore next */ {
        return null;
    }
}
async function getHashFromUrl(url) {
    try {
        const parsedUrl = url_1.parse(url);
        const filename = path_1.default.basename(parsedUrl.pathname);
        let hash;
        hash = await getHashFromFile(filename + '.sha256', filename);
        if (hash) {
            return hash;
        }
        hash = await getHashFromFile(url.replace(filename, 'SHA256SUMS'), filename);
        if (hash) {
            return hash;
        }
        hash = await hasha_1.fromStream(http.stream(url), {
            algorithm: 'sha256',
        });
        return hash;
    }
    catch (err) /* istanbul ignore next */ {
        return null;
    }
}
async function updateDependency({ fileContent, upgrade, }) {
    if (upgrade.depType === 'ironbank-docker') {
        const oldTag = upgrade.lookupName + ':' + upgrade.currentValue;
        const newTag = upgrade.lookupName + ':' + upgrade.newValue;
        let newContent = fileContent.replace(upgrade.currentDigest, upgrade.newDigest);
        return newContent.replace(oldTag, newTag);
    }
    else if (upgrade.depType === 'ironbank-github' &&
        upgrade.currentValue &&
        upgrade.newValue) {
        const currentValue = upgrade.currentValue.replace(/^v/, '');
        const newValue = upgrade.newValue.replace(/^v/, '');
        const oldUrl = upgrade.managerData.item.url;
        const newUrl = oldUrl.replace(new RegExp(currentValue, 'g'), newValue);
        const hash = await getHashFromUrl(newUrl);
        let newContent = fileContent;
        if (hash) {
            newContent = newContent.replace(upgrade.managerData.item.validation.value, hash);
        }
        return newContent.replace(oldUrl, newUrl);
    }
    return null;
}
exports.updateDependency = updateDependency;
//# sourceMappingURL=update.js.map