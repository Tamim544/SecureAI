/**
 * SecureAI GitHub PR Bot
 * Built with Probot
 */

const axios = require('axios');
require('dotenv').config();

const API_URL = process.env.SECUREAI_API_URL || 'http://localhost:8000';

module.exports = (app) => {
  app.log.info("SecureAI Bot was loaded!");

  app.on(["pull_request.opened", "pull_request.synchronize"], async (context) => {
    const pr = context.payload.pull_request;
    
    app.log.info(`Scanning PR #${pr.number} in ${context.payload.repository.full_name}`);
    
    // Fetch the changed files in the PR
    const files = await context.octokit.pulls.listFiles(context.repo({
      pull_number: pr.number
    }));
    
    const targetExtensions = ['.py', '.js', '.jsx', '.ts', '.tsx'];
    
    // Filter for files we can analyze
    const scannableFiles = files.data.filter(file => {
      const ext = file.filename.substring(file.filename.lastIndexOf('.'));
      return targetExtensions.includes(ext) && file.status !== 'removed';
    });
    
    if (scannableFiles.length === 0) {
      app.log.info("No scannable files found in PR.");
      return;
    }
    
    // Create a check run
    const checkRun = await context.octokit.checks.create(context.repo({
      name: 'SecureAI Vulnerability Scan',
      head_sha: pr.head.sha,
      status: 'in_progress'
    }));
    
    let totalFindings = 0;
    const annotations = [];
    
    // Analyze each file
    for (const file of scannableFiles) {
      try {
        // Get file content
        const content = await context.octokit.repos.getContent(context.repo({
          path: file.filename,
          ref: pr.head.sha
        }));
        
        const decodedContent = Buffer.from(content.data.content, 'base64').toString();
        const ext = file.filename.substring(file.filename.lastIndexOf('.'));
        const language = ext === '.py' ? 'python' : 'javascript';
        
        // Call SecureAI API
        const response = await axios.post(`${API_URL}/api/v1/scan/snippet`, {
          code: decodedContent,
          language: language,
          filename: file.filename
        });
        
        const findings = response.data.findings || [];
        totalFindings += findings.length;
        
        // Map findings to GitHub check run annotations
        for (const finding of findings) {
          let annotationLevel = 'warning';
          if (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') {
            annotationLevel = 'failure';
          }
          
          annotations.push({
            path: file.filename,
            start_line: finding.line_start,
            end_line: finding.line_end,
            annotation_level: annotationLevel,
            title: `[${finding.cwe_id}] ${finding.severity} Vulnerability`,
            message: `${finding.description}\n\nSuggested Fix:\n${finding.fix_suggestion}`
          });
        }
        
      } catch (error) {
        app.log.error(`Failed to scan ${file.filename}: ${error.message}`);
      }
    }
    
    // Complete the check run
    const conclusion = totalFindings > 0 ? 'action_required' : 'success';
    
    await context.octokit.checks.update(context.repo({
      check_run_id: checkRun.data.id,
      status: 'completed',
      conclusion: conclusion,
      output: {
        title: totalFindings > 0 ? `SecureAI found ${totalFindings} vulnerabilities` : 'SecureAI found no vulnerabilities',
        summary: `We scanned ${scannableFiles.length} files and found ${totalFindings} issues.`,
        annotations: annotations.slice(0, 50) // GitHub API limit is 50 annotations per request
      }
    }));
  });
};
