export interface AnalyzeRequest {
  message?: string | null;
  url?: string | null;
}

export type RiskLevel = 'Low' | 'Medium' | 'High';

export interface AnalyzeResponse {
  risk_score: number;
  risk_level: RiskLevel;
  indicators: string[];
  recommendation: string;
  analysis_method: string;
}

export interface ApiErrorResponse {
  detail?: string | Array<{ msg?: string; loc?: string[] }>;
}

