export type PipelineEventType = 'retrieval' | 'generation' | 'output' | 'custom';
export type ComplianceFramework = 'eu_ai_act' | 'soc2' | 'gdpr' | 'hipaa' | 'custom';
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface PipelineEventPayload {
  // Option: True defaults to scrubbing SSNs, IPs, emails natively off client systems.
  scrubPii?: boolean;
  
  eventType: PipelineEventType;
  stepName?: string;
  payload: Record<string, any>;
  pipelineId?: string;
  complianceFramework?: string;
  riskLevel?: string;
  userId?: string;
  sessionId?: string;
  modelId?: string;
  modelVersion?: string;
  promptTokens?: number;
  completionTokens?: number;
  totalCost?: number;
  latencyMs?: number;
  piiDetected?: boolean;
  toxicityScore?: number;
  groundingScore?: number;
  userFeedback?: number;
  temperature?: number;
  maxTokens?: number;
  topP?: number;
  systemPromptHash?: string;
  contextLength?: number;
  generationSpeed?: number;
  stopReason?: string;
}

export interface PipelineEventResult {
  id: string;
  organizationId: string;
  pipelineId: string | null;
  eventType: PipelineEventType;
  stepName: string | null;
  payload: any;
  payloadHash: string;
  txSignature: string | null;
  pdaAddress: string | null;
  anchorStatus: 'PENDING' | 'CONFIRMED' | 'FAILED';
  anchoredAt: string | null;
  blockNumber: string | null;
  blockTimestamp: string | null;
  complianceFramework: string | null;
  riskLevel: string | null;
  userId: string | null;
  sessionId: string | null;
  modelId: string | null;
  modelVersion: string | null;
  verificationUrl: string | null;
  createdAt: string;
  promptTokens: number | null;
  completionTokens: number | null;
  totalCost: number | null;
  latencyMs: number | null;
  piiDetected: boolean;
  toxicityScore: number | null;
  groundingScore: number | null;
  userFeedback: number | null;
  explorerUrl: string | null;
  pdaExplorerUrl: string | null;
}

export interface BatchPipelineEventPayload {
  events: PipelineEventPayload[];
}

export interface BatchPipelineEventResult {
  summary: {
    total: number;
    anchored: number;
    failed: number;
  };
  results: any[];
}

export interface PipelineConfig {
  id: string;
  organizationId: string;
  name: string;
  framework: 'langchain' | 'pathway' | 'llamaindex' | 'custom' | null;
  description: string | null;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
  eventCount?: number;
}

export interface PipelineSessionSummary {
  sessionId: string;
  totalEvents: number;
  confirmedEvents: number;
  eventTypes: string[];
  startedAt: string;
  endedAt: string;
  durationMs: number;
  isComplete: boolean;
}
